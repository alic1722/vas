layui.use(function(){
  var upload = layui.upload;
  var layer = layui.layer;
  var element = layui.element;
  var $ = layui.$;
  // 单图片上传
  var uploadInst = upload.render({
    elem: '#ID-upload-demo-btn',
    url: 'http://127.0.0.1:5000/uploadImg', // 实际使用时改成您自己的上传接口即可。
    before: function(obj){
      // 预读本地文件示例，不支持ie8
      obj.preview(function(index, file, result){
        $('#ID-upload-demo-img').attr('src', result); // 图片链接（base64）
      });

      element.progress('filter-demo', '0%'); // 进度条复位
      layer.msg('上传中', {icon: 16, time: 0});
    },
    done: function(res){
      console.log(res)
      // 若上传失败
      if(res.code !== 200){
        $('#ID-upload-demo-text').html(''); // 置空上传失败的状态
        return layer.msg('上传失败!');
      }else{
        // 上传成功的一些操作
        // …
        console.log('上传成功')
        $('#ID-upload-demo-text').html(res.data); // 置空上传失败的状态
        // return layer.msg('');
      }


    },
    error: function(){
      // 演示失败状态，并实现重传
      var demoText = $('#ID-upload-demo-text');
      demoText.html('<span style="color: #FF5722;">上传失败</span> <a class="layui-btn layui-btn-xs demo-reload">重试</a>');
      demoText.find('.demo-reload').on('click', function(){
        uploadInst.upload();
      });
    },
    // 进度条
    progress: function(n, elem, e){
      element.progress('filter-demo', n + '%'); // 可配合 layui 进度条元素使用
      if(n == 100){
        layer.msg('上传完毕!', {icon: 1});
      }
    }
  });

  //单视频上传
  var uploadVideo = upload.render({
    elem: '#ID-upload-video-btn',
    accept: 'video/*',
    url: 'http://127.0.0.1:5000/uploadVideo', // 实际使用时改成您自己的上传接口即可。
    before: function(obj){
      // 预读本地文件示例，不支持ie8
      obj.preview(function(index, file, result){
        $('#originalVideo').attr('src', result); // 图片链接（base64）
      });

      element.progress('filter-video', '0%'); // 进度条复位
      layer.msg('上传中', {icon: 16, time: 0});
    },
    done: function(res){
      // 若上传失败
      if(res.code !== 200){
        $('#ID-upload-video-text').html(''); // 置空上传失败的状态
        return layer.msg('上传失败!');
      }else{
        // 上传成功的一些操作
        // …
        console.log('上传成功')
        $('#ID-upload-video-text').html(res.data); // 置空上传失败的状态
        // return layer.msg('');
      }
      // const videoBlob = res.blob();
      // const videoUrl = URL.createObjectURL(videoBlob);
      // console.log(videoUrl,211)
      // $('#processedVideo').attr('src',videoUrl)
    },
    error: function(){
      // 演示失败状态，并实现重传
      var demoText = $('#ID-upload-demo-text');
      demoText.html('<span style="color: #FF5722;">上传失败</span> <a class="layui-btn layui-btn-xs demo-reload">重试</a>');
      demoText.find('.demo-reload').on('click', function(){
        uploadVideo.upload();
      });
    },
    // 进度条
    progress: function(n, elem, e){
      element.progress('filter-video', n + '%'); // 可配合 layui 进度条元素使用
      if(n == 100){
        layer.msg('上传完毕!', {icon: 1});
      }
    }
  });

  //下拉菜单选择
  var dropdown = layui.dropdown;
  // 渲染
  dropdown.render({
    elem: '.demo-dropdown-base', // 绑定元素选择器，此处指向 class 可同时绑定多个元素
    data: [{
      title: 'yolov5s',
      id: 100
    },{
      title: 'yolov5x',
      id: 101
    },{
      title: 'elec-bike',
      id: 102
    }],
    click: function(obj){
      this.elem.find('span').text(obj.title);
    }
  });
  dropdown.render({
    elem: '#demo-dropdown-device', // 绑定元素选择器，此处指向 class 可同时绑定多个元素
    data: [{
      title: 'RTSP海康',
      id: 100
    },{
      title: '我的手机',
      id: 101
    },{
      title: '我的电脑',
      id: 102
    }],
    click: function(obj){
      this.elem.find('span').text(obj.title);
    }
  });
  //开始预测图片按钮点击
  $('#start-predict-btn').on('click', function(){
    my_img = $('#ID-upload-demo-img').attr('src')
    //判断是否选择了图片
    if(!my_img)
      return layer.msg('请选择要预测的图片!', {
        icon: 2,    // 1表示成功的图标
        time: 2000, // 消息显示时间
        shade: 0.5, // 遮罩透明度
        style: {
          color: '#fff', // 文字颜色
          backgroundColor: '#ffb800' // 背景颜色
        }
      });
    let my_model = $('#dropdown-model-text').text()
    //判断是否选择了模型
    if(my_model==='选择模型')
      return layer.msg('请选择一个模型!', {
        icon: 2,    // 1表示成功的图标
        time: 2000, // 消息显示时间
        shade: 0.5, // 遮罩透明度
        style: {
          color: '#fff', // 文字颜色
          backgroundColor: '#ffb800' // 背景颜色
        }
      });
    var previewImage = document.getElementById('ID-upload-demo-img');

    // 创建一个 Canvas 元素
    var canvas = document.createElement('canvas');
    var ctx = canvas.getContext('2d');

    canvas.width = previewImage.width;
    canvas.height = previewImage.height;
    // 将图片绘制到 Canvas 上
    ctx.drawImage(previewImage, 0, 0, canvas.width, canvas.height);
    // 将 Canvas 转换为 Blob 对象
    canvas.toBlob(function (blob) {
      var formData = new FormData();
      formData.append('image', blob, 'image.jpg');
      // 发送异步请求
    axios.post('/start_img_predict', formData)
      .then(function(response) {
        resp = response.data
        if(resp.code===200){
          // 显示图片
          var resultImage = document.getElementById('ID-show-demo-img');
          resultImage.src = resp.data;
          return layer.msg('预测完成', {
            icon: 1,    // 1表示成功的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#34da84' // 背景颜色
            }
          });
        }else{
          return layer.msg('预测失败,非法传递数据!', {
            icon: 2,    // 2表示失败的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#e23f32' // 背景颜色
            }
          });
        }
        // 处理成功响应

        // 关闭加载层
        // layer.close(loadingIndex);

        // 这里可以根据响应的数据执行其他操作
      })
      .catch(function(error) {
        // 处理错误
        console.error(error);

        // 关闭加载层
        // layer.close(loadingIndex);

        // 弹出错误提示
        layer.msg('请求失败，请重试');
      });
    },'image/jpeg');


  });

  //开始预测视频按钮点击
  $('#start-predict-btn1').on('click', function(){
    my_video = $('#originalVideo').attr('src')
    //判断是否选择了图片
    if(!my_video)
      return layer.msg('请选择要预测的视频!', {
        icon: 2,    // 1表示成功的图标
        time: 2000, // 消息显示时间
        shade: 0.5, // 遮罩透明度
        style: {
          color: '#fff', // 文字颜色
          backgroundColor: '#ffb800' // 背景颜色
        }
      });
    let my_model = $('#dropdown-model-text1').text()
    //判断是否选择了模型
    if(my_model==='选择模型')
      return layer.msg('请选择一个模型!', {
        icon: 2,    // 1表示成功的图标
        time: 2000, // 消息显示时间
        shade: 0.5, // 遮罩透明度
        style: {
          color: '#fff', // 文字颜色
          backgroundColor: '#ffb800' // 背景颜色
        }
      });
    // 在发送 Axios 请求之前显示加载动画
    let loadingIndex = layer.load(1, {
      content: '正在预测中...', // 加载提示的内容
      shade: [0.5, '#fff'], // 遮罩的透明度和颜色
    });
    axios.post('/start_video_predict', { filename: uploadedVideoFilename })
      .then(function(response) {
        layer.close(loadingIndex);
        resp = response.data
        if(resp.code===200){
          console.log(resp.data)
          //获取的是url地址，
          //必须是完整的路径地址
          // perfect_path = 'http://localhost:5000'+response.data
          $('#processedVideo').attr('src',resp.data)
          return layer.msg('预测完成', {
            icon: 1,    // 1表示成功的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#34da84' // 背景颜色
            }
          });
        }else{
          return layer.msg('预测失败,非法传递数据!', {
            icon: 2,    // 2表示失败的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#e23f32' // 背景颜色
            }
          });
        }
        // 处理成功响应

        // 关闭加载层
        // layer.close(loadingIndex);

        // 这里可以根据响应的数据执行其他操作
      })
      .catch(function(error) {
        // 处理错误
        console.error(error);
        layer.close(loadingIndex);
        // 关闭加载层
        // layer.close(loadingIndex);

        // 弹出错误提示
        layer.msg('请求失败，请重试');
      });
    });

  //打开摄像头
  $('#ID-open-camera-btn').on('click',function (){
      let my_device = $('#dropdown-model-camera_type').text()
      if(my_device==='选择设备')
        return layer.msg('请选择打开设备!', {
          icon: 2,    // 1表示成功的图标
          time: 2000, // 消息显示时间
          shade: 0.5, // 遮罩透明度
          style: {
            color: '#fff', // 文字颜色
            backgroundColor: '#ffb800' // 背景颜色
          }
        });
      switch (my_device){
        case 'RTSP海康':my_device='haikang';break
        case '我的手机':my_device='phone';break
        case '我的电脑':my_device='computer';break
      }
      axios.post(`/open_camera/${my_device}`).then(function(response){
        resp = response.data
        if(resp.code===200){
          //让图片加载摄像头信息
          $('#originalCamera').attr('src',"/video_start")

          return layer.msg(resp.msg, {
            icon: 1,    // 1表示成功的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#34da84' // 背景颜色
            }
          });
        }else{
          return layer.msg(resp.msg, {
            icon: 2,    // 1表示成功的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#e23f32' // 背景颜色
            }
          });
        }
      }).catch(function(error) {
        // 处理错误
        console.error(error);
        // layer.close(loadingIndex);
        // 关闭加载层
        // layer.close(loadingIndex);

        // 弹出错误提示
        layer.msg('请求失败，请重试');
      });
  })

  //关闭摄像头
  $('#ID-close-camera-btn').on('click',function (){
      axios.post('close_camera').then(function(response){
        resp = response.data
        if(resp.code===200){
          //让图片加载摄像头信息
          // $('#originalCamera').attr('src','')
          $('#processedCamera').attr('src','')
          setTimeout(()=>{
            console.log('摄像头已关闭!')
          },10)
          $('#start-predict-btn2').attr('disabled',false)
          return layer.msg(resp.msg, {
            icon: 1,    // 1表示成功的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#34da84' // 背景颜色
            }
          });
        }else{
          return layer.msg(resp.msg, {
            icon: 2,    // 1表示成功的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#e23f32' // 背景颜色
            }
          });
        }
      }).catch(function(error) {
        // 处理错误
        console.error(error);
        // layer.close(loadingIndex);
        // 关闭加载层
        // layer.close(loadingIndex);

        // 弹出错误提示
        layer.msg('还未打开摄像头!', {icon: 2});
      });
  })

  //摄像头检测开始
  $('#start-predict-btn2').on('click', function(){
    // my_camera= $('#originalCamera').attr('src')
    // //判断是否选择了图片
    // if(!my_camera)
    //   return layer.msg('请先打开摄像头!', {
    //     icon: 2,    // 1表示成功的图标
    //     time: 2000, // 消息显示时间
    //     shade: 0.5, // 遮罩透明度
    //     style: {
    //       color: '#fff', // 文字颜色
    //       backgroundColor: '#ffb800' // 背景颜色
    //     }
    //   });
    let my_model = $('#dropdown-model-text2').text()

    //判断是否选择了模型
    if(my_model==='选择模型')
      return layer.msg('请选择一个模型!', {
        icon: 2,    // 1表示成功的图标
        time: 2000, // 消息显示时间
        shade: 0.5, // 遮罩透明度
        style: {
          color: '#fff', // 文字颜色
          backgroundColor: '#ffb800' // 背景颜色
        }
      });
    let my_device = $('#dropdown-model-camera_type').text()
    if(my_device==='选择设备')
      return layer.msg('请选择打开设备!', {
        icon: 2,    // 1表示成功的图标
        time: 2000, // 消息显示时间
        shade: 0.5, // 遮罩透明度
        style: {
          color: '#fff', // 文字颜色
          backgroundColor: '#ffb800' // 背景颜色
        }
      });
    switch (my_device){
      case 'RTSP海康':my_device='haikang';break
      case '我的手机':my_device='phone';break
      case '我的电脑':my_device='computer';break
    }
    //检测之前先把处理后的摄像头置空
    $('#processedCamera').attr('src',``)
    // 在发送 Axios 请求之前显示加载动画
    let loadingIndex = layer.load(1, {
      content: '正在预测中...', // 加载提示的内容
      shade: [0.5, '#fff'], // 遮罩的透明度和颜色
    });
    axios.post('/start_camera_predict', { device: my_device, model: my_model })
      .then(function(response) {
        layer.close(loadingIndex);
        resp = response.data
        if(resp.code===200){
          $('#start-predict-btn2').attr('disabled',true)
          // console.log(resp.data)
          //获取的是url地址，
          //必须是完整的路径地址
          // perfect_path = 'http://localhost:5000'+response.data
          $('#processedCamera').attr('src',`/get_camera_det_result`)
          return layer.msg('正在检测...', {
            icon: 1,    // 1表示成功的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#34da84' // 背景颜色
            }
          });
        }else{
          return layer.msg('检测失败,非法传递数据!', {
            icon: 2,    // 2表示失败的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#e23f32' // 背景颜色
            }
          });
        }
        // 处理成功响应

        // 关闭加载层
        // layer.close(loadingIndex);

        // 这里可以根据响应的数据执行其他操作
      })
      .catch(function(error) {
        // 处理错误
        console.error(error);
        layer.close(loadingIndex);
        // 关闭加载层
        // layer.close(loadingIndex);

        // 弹出错误提示
        layer.msg('请求失败，请重试');
      });
    });

  //单视频上传 ***plus版本
  var uploadVideo1 = upload.render({
    elem: '#ID-upload-video-btn1',
    accept: 'video/*',
    url: 'http://127.0.0.1:5000/uploadVideo1', // 实际使用时改成您自己的上传接口即可。
    before: function(obj){
      // 预读本地文件示例，不支持ie8
      obj.preview(function(index, file, result){
        $('#originalVideo1').attr('src', result); // 图片链接（base64）
      });

      element.progress('filter-video', '0%'); // 进度条复位
      layer.msg('上传中', {icon: 16, time: 0});
    },
    done: function(res){
      // 若上传失败
      if(res.code !== 200){
        $('#ID-upload-video-text1').html(''); // 置空上传失败的状态
        return layer.msg('上传失败!');
      }else{
        // 上传成功的一些操作
        // …
        console.log('上传成功')
        $('#ID-upload-video-text1').html(res.data); // 置空上传失败的状态
        // return layer.msg('');
      }
      // const videoBlob = res.blob();
      // const videoUrl = URL.createObjectURL(videoBlob);
      // console.log(videoUrl,211)
      // $('#processedVideo').attr('src',videoUrl)
    },
    error: function(){
      // 演示失败状态，并实现重传
      var demoText = $('#ID-upload-demo-text1');
      demoText.html('<span style="color: #FF5722;">上传失败</span> <a class="layui-btn layui-btn-xs demo-reload">重试</a>');
      demoText.find('.demo-reload').on('click', function(){
        uploadVideo.upload();
      });
    },
    // 进度条
    progress: function(n, elem, e){
      element.progress('filter-video1', n + '%'); // 可配合 layui 进度条元素使用
      if(n == 100){
        layer.msg('上传完毕!', {icon: 1});
      }
    }
  });

  //开始预测视频按钮点击--plusplus***
  $('#start-predict-btn3').on('click', function(){
    my_video = $('#originalVideo1').attr('src')
    //判断是否选择了图片
    if(!my_video)
      return layer.msg('请选择要预测的视频!', {
        icon: 2,    // 1表示成功的图标
        time: 2000, // 消息显示时间
        shade: 0.5, // 遮罩透明度
        style: {
          color: '#fff', // 文字颜色
          backgroundColor: '#ffb800' // 背景颜色
        }
      });
    let my_model = $('#dropdown-model-text3').text()
    //判断是否选择了模型
    if(my_model==='选择模型')
      return layer.msg('请选择一个模型!', {
        icon: 2,    // 1表示成功的图标
        time: 2000, // 消息显示时间
        shade: 0.5, // 遮罩透明度
        style: {
          color: '#fff', // 文字颜色
          backgroundColor: '#ffb800' // 背景颜色
        }
      });
    //点击开始预测之前，先清空检测的src
    $('#processedVideo1').attr('src','')
    console.log('清空记录!')
    // 在发送 Axios 请求之前显示加载动画
    let loadingIndex = layer.load(1, {
      content: '正在预测中...', // 加载提示的内容
      shade: [0.5, '#fff'], // 遮罩的透明度和颜色
    });
    axios.post(`/start_video1_predict/${my_model}`,{ withCredentials: true }).then(function(response) {
        layer.close(loadingIndex);
        resp = response.data
        if(resp.code===200){
          console.log(resp.data)
          //获取的是url地址，
          //必须是完整的路径地址
          // perfect_path = 'http://localhost:5000'+response.data
          $('#processedVideo1').attr('src','/get_video1_det_result')
          return layer.msg('预测完成', {
            icon: 1,    // 1表示成功的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#34da84' // 背景颜色
            }
          });
        }else{
          return layer.msg('预测失败,非法传递数据!', {
            icon: 2,    // 2表示失败的图标
            time: 2000, // 消息显示时间
            shade: 0.5, // 遮罩透明度
            style: {
              color: '#fff', // 文字颜色
              backgroundColor: '#e23f32' // 背景颜色
            }
          });
        }
        // 处理成功响应

        // 关闭加载层
        // layer.close(loadingIndex);

        // 这里可以根据响应的数据执行其他操作
      })
      .catch(function(error) {
        // 处理错误
        console.error(error);
        layer.close(loadingIndex);
        // 关闭加载层
        // layer.close(loadingIndex);

        // 弹出错误提示
        layer.msg('请求失败，请重试');
      });
    });
});
