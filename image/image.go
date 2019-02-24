package image

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/neo-hu/test_container/gotty"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
)

const (
	manifestUrl = "/v2/%s/manifests/latest"
	blobUrl     = "/v2/%s/blobs/%s"
)

var ImageTypes = []string{
	MediaTypeImageConfig,
	MediaTypeImageConfig,
	"application/octet-stream",
	"application/json",
	"text/html",
	"",
}

func pullManifests(client *http.Client, base *url.URL, path string) (Manifest, error) {
	routeURL, err := url.Parse(fmt.Sprintf(manifestUrl, path))
	if err != nil {
		return Manifest{}, err
	}
	u := base.ResolveReference(routeURL)
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return Manifest{}, err
	}
	req.Header.Add("Accept", MediaTypeManifest)
	resp, err := client.Do(req)
	if err != nil {
		return Manifest{}, err
	}
	defer resp.Body.Close()
	if SuccessStatus(resp.StatusCode) {
		mt := resp.Header.Get("Content-Type")
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return Manifest{}, err
		}
		m, _, err := UnmarshalManifest(mt, body)
		if err != nil {
			return Manifest{}, err
		}
		return m, nil
	} else {
		return Manifest{}, HandleErrorResponse(resp)
	}
}

// todo 根据Content-Type解析Manifest
func UnmarshalManifest(ctHeader string, b []byte) (Manifest, Descriptor, error) {
	var mediaType string
	if ctHeader != "" {
		var err error
		mediaType, _, err = mime.ParseMediaType(ctHeader)
		if err != nil {
			return Manifest{}, Descriptor{}, err
		}
	}
	switch mediaType {
	case MediaTypeManifest:
		canonical := make([]byte, len(b), len(b))
		copy(canonical, b)
		var manifest Manifest
		if err := json.Unmarshal(canonical, &manifest); err != nil {
			return Manifest{}, Descriptor{}, err
		}
		dgst := digest.FromBytes(b)
		return manifest, Descriptor{Digest: dgst, Size: int64(len(b)), MediaType: MediaTypeManifest}, nil

	}
	return Manifest{}, Descriptor{}, fmt.Errorf("unsupported manifest media type and no default available: %s", mediaType)
}

func PullImage(ctx context.Context, rootDir, image string) (*Image, *Layer, error) {
	domain, remainder := splitDockerDomain(image)
	base, err := url.Parse("https://" + domain)
	if err != nil {
		return nil, nil, err
	}

	client := &http.Client{
		Transport: NewTransport(NewTokenHandlerWithOptions(base, remainder)),
	}

	logrus.Infof("Pulling Manifests ")
	manifest, err := pullManifests(client, base, remainder)
	if err != nil {
		return nil, nil, err
	}
	var allowedMediatype bool
	for _, t := range ImageTypes {
		if manifest.Config.MediaType == t {
			allowedMediatype = true
			break
		}
	}
	if !allowedMediatype {
		return nil, nil, fmt.Errorf("Encountered remote %s when fetching", manifest.Config.MediaType)
	}
	logrus.Infof("Pulling ref from V2 registry: %s %s", domain, remainder)
	return pullSchema2(rootDir, client, manifest, base, remainder)
}

func pullSchema2(rootDir string, client *http.Client, mfst Manifest, base *url.URL, path string) (*Image, *Layer, error) {
	imageChan := make(chan *Image, 1)
	imageErrChan := make(chan error, 1)

	go func() {
		// todo 下载配置文件
		configJSON, err := pullSchema2Config(client, mfst.Config, base, path)
		if err != nil {
			imageErrChan <- err
			return
		}
		imageChan <- configJSON
	}()

	// todo 下载 layers
	layerDone := make(chan *Layer, 1)
	layerErrChan := make(chan error, 1)

	err := os.MkdirAll(rootDir, 0755)
	if err != nil {
		return nil, nil, err
	}
	go func() {
		layer, err := download(rootDir, client, mfst.Layers, base, path)
		if err != nil {
			layerErrChan <- err
			return
		}
		layerDone <- layer
	}()
	var (
		image *Image
	)
	select {
	case image = <-imageChan:
	case err := <-imageErrChan:
		return nil, nil, err
	}

	select {
	case layer := <-layerDone:
		var diffIDs []digest.Digest
		l := layer
		for range mfst.Layers {
			if l == nil {
				return nil, nil, errors.New("internal error: too few parent layers")
			}
			diffIDs = append([]digest.Digest{l.diffID}, diffIDs...)
			l = l.parent
		}
		// 比较diff_ids是否一致
		if len(diffIDs) != len(image.RootFS.DiffIDs) {
			return nil, nil, errors.New("layers from manifest don't match image configuration")
		}
		for i := range diffIDs {
			if diffIDs[i] != image.RootFS.DiffIDs[i] {
				return nil, nil, errors.New("layers from manifest don't match image configuration")
			}
		}
		return image, layer, nil
	case err := <-layerErrChan:
		return nil, nil, err
	}

}

type Layer struct {
	parent *Layer
	diffID digest.Digest
	root   string
}

func (l *Layer) Parent() *Layer {
	return l.parent
}

func (l *Layer) Dir() string {
	return l.root
}

type downloadTransfer struct {
	running chan struct{}
	layer   *Layer
	err     error
}

func (d *downloadTransfer) setResult(layer *Layer, err error) {
	d.err = err
	if err != nil {
		panic(err)
	}
	d.layer = layer
	close(d.running)
}

type DoFunc func() *downloadTransfer

// 并行下载Layers
func download(rootDir string, client *http.Client, layers []Descriptor, base *url.URL, p string) (*Layer, error) {
	progress, _ := gotty.NewProgress(context.Background(), os.Stdout)
	var progressOut chan gotty.ProgressMessage
	if progress != nil {
		progressOut = progress.Output
		defer progress.Cancel()
		progress.Run()
	}
	if err := MkdirAll(rootDir, 0755); err != nil {
		return nil, err
	}

	var makeDownloadFuncFromDownload = func(l Descriptor, parentDownload *downloadTransfer, progress chan<- gotty.ProgressMessage) DoFunc {
		return func() *downloadTransfer {
			d := &downloadTransfer{
				running: make(chan struct{}),
			}

			id := TruncateID(l.Digest.String())
			root := path.Join(rootDir, l.Digest.String())
			diffIdFile := path.Join(root, "diff-id")
			go func() {
				if parentDownload != nil {
					// todo 如果前一次下载出错，没必要下载其他的数据
					select {
					case <-parentDownload.running:
						if parentDownload.err != nil {
							d.setResult(nil, parentDownload.err)
							return
						}
					default:
					}
				}
				// todo 判断是否已经下载
				f, err := os.Stat(root)
				if err == nil {
					if !f.IsDir() {
						d.setResult(nil, fmt.Errorf("%s is not dir", root))
						return
					}
					diffByte, err := ioutil.ReadFile(diffIdFile)
					if err != nil {
						if os.IsNotExist(err) {
							logrus.Warnf("%s does not exist", diffIdFile)
							if err := os.RemoveAll(root); err != nil {
								d.setResult(nil, err)
								return
							}
						} else {
							d.setResult(nil, err)
							return
						}
					}
					diffID, err := digest.Parse(string(diffByte))
					if err != nil {
						logrus.Warnf("%s parse err:%v", diffIdFile, err)
						if err := os.RemoveAll(root); err != nil {
							d.setResult(nil, err)
							return
						}
					} else {
						layer := &Layer{
							diffID: diffID,
							root:   root,
						}
						if parentDownload != nil {
							// todo 这里必须等待上一个下载完成
							select {
							case <-parentDownload.running:
								if parentDownload.err != nil {
									d.setResult(nil, parentDownload.err)
									return
								}
							}
							layer.parent = parentDownload.layer
						}

						progress <- gotty.ProgressMessage{
							Id:     id,
							Prefix: fmt.Sprintf("%s: Download complete for cache", id),
						}
						d.setResult(layer, nil)
					}
				} else if !os.IsNotExist(err) {
					d.setResult(nil, err)
					return
				}

				routeURL, err := url.Parse(fmt.Sprintf(blobUrl, p, l.Digest.String()))
				if err != nil {
					d.setResult(nil, err)
					return
				}
				//cacheFile := path.Join(cacheDir, l.Digest.String())
				//tmp, err := ioutil.TempFile(cacheDir, "GetImageBlob")
				//if err != nil {
				//	d.setResult(nil, err)
				//	return
				//}
				//logrus.Infof("download %s to %s", id, tmp.Name())
				layerDownload := NewHTTPReadSeeker(client, base.ResolveReference(routeURL).String(), func(reps *http.Response) error {
					return HandleErrorResponse(reps)
				})
				var reader io.ReadCloser
				// todo 如果http服务器支持 Range， 尝试计算文件大小
				size, err := layerDownload.Seek(0, os.SEEK_END)
				if err != nil {
					reader = layerDownload
				} else {
					_, err = layerDownload.Seek(0, os.SEEK_SET)
					if err != nil {
						d.setResult(nil, err)
						//tmp.Close()
						return
					}
					// todo 下载进度
					reader = NewProgressReader(layerDownload, size, func(current, size int64, speed float64) {
						if current == size {
							// Download complete
						} else {
							if progress != nil {
								progress <- gotty.ProgressMessage{
									Id:      id,
									Prefix:  fmt.Sprintf("%s: Downloading", id),
									Total:   size,
									Current: current,
									Suffix: fmt.Sprintf("%s/%s", BytesSize(float64(current)),
										BytesSize(float64(size))),
								}
							}
						}
					})
				}
				defer reader.Close()
				if parentDownload != nil {
					// todo 如果前一次下载出错，没必要处理剩下的逻辑
					select {
					case <-parentDownload.running:
						if parentDownload.err != nil {
							d.setResult(nil, parentDownload.err)
							return
						}
					default:
					}
				}
				digester := digest.Canonical.Digester()
				// todo 解压
				decompressReader, err := DecompressStream(reader)
				if err != nil {
					d.setResult(nil, err)
					return
				}
				// todo 下载到临时目录，下载完成后重命名
				tmpDir, err := ioutil.TempDir(rootDir, "GetImageBlob")
				if err != nil {
					d.setResult(nil, err)
					return
				}

				if err := applyTar(io.TeeReader(decompressReader, digester.Hash()), path.Join(tmpDir, "diff")); err != nil {
					d.setResult(nil, err)
					return
				}
				if err := os.RemoveAll(root); err != nil {
					d.setResult(nil, err)
					return
				}
				if err := os.Rename(tmpDir, root); err != nil {
					d.setResult(nil, err)
					return
				}
				layer := &Layer{
					diffID: digester.Digest(),
					root:   root,
				}
				// todo 写入 diffID
				if err := ioutil.WriteFile(diffIdFile, []byte(layer.diffID), 0644); err != nil {
					d.setResult(nil, err)
					return
				}

				progress <- gotty.ProgressMessage{
					Id: id,
					Prefix: fmt.Sprintf("%s: Download complete %s, wait for parent", id,
						BytesSize(float64(size))),
				}
				if parentDownload != nil {
					// todo 这里必须等待上一个下载完成
					select {
					case <-parentDownload.running:
						if parentDownload.err != nil {
							d.setResult(nil, parentDownload.err)
							return
						}
					}
					layer.parent = parentDownload.layer
				}
				progress <- gotty.ProgressMessage{
					Id: id,
					Prefix: fmt.Sprintf("%s: Download complete %s", id,
						BytesSize(float64(size))),
				}
				d.setResult(layer, nil)
			}()
			return d
		}
	}

	var parentDownload *downloadTransfer
	var xferFunc DoFunc
	for _, l := range layers {
		if parentDownload != nil {
			xferFunc = makeDownloadFuncFromDownload(l, parentDownload, progressOut)
		} else {
			xferFunc = makeDownloadFuncFromDownload(l, nil, progressOut)
		}
		parentDownload = xferFunc()
	}
	// todo 最后一个layers 下载完成
	<-parentDownload.running
	if parentDownload.err != nil {
		return nil, parentDownload.err
	}
	return parentDownload.layer, nil
}

func pullSchema2Config(client *http.Client, config Descriptor, base *url.URL, path string) (*Image, error) {
	configURL, err := url.Parse(fmt.Sprintf(blobUrl, path, config.Digest.String()))
	if err != nil {
		return nil, err
	}
	configURL = base.ResolveReference(configURL)
	logrus.Debugf("get config %s", configURL.String())
	resp, err := client.Get(configURL.String())
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	if !SuccessStatus(resp.StatusCode) {
		return nil, HandleErrorResponse(resp)
	}
	imageConfig := &Image{}
	if err := json.NewDecoder(resp.Body).Decode(imageConfig); err != nil {
		return nil, err
	}
	return imageConfig, nil
}
