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
        //将模型传入，并且获取图片
        // 显示加载层
        // var loadingIndex = layer.load(1, {
        //   content: '正在加载中...', // 加载提示的内容
        //   shade: [0.5, '#fff'], // 遮罩的透明度和颜色
        //   success: function (layero) {
        //     layero.find('.layui-layer-content').css({
        //       'padding-top': '40px',
        //       'text-align': 'center'
        //     });
        //   }
        // });
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
        axios.post(`/start_predict/${my_model}`,formData,{
            headers: {
              'Content-Type': 'multipart/form-data'
            },
            responseType: 'arraybuffer' // 设置响应数据类型为二进制数据
        }).then(function(response) {
            console.log(response.status)
            if(response.status===200){
              var buffer = response.data; // 获取后端返回的二进制数据
              var blob = new Blob([buffer]); // 创建二进制对象
              var imageUrl = URL.createObjectURL(blob); // 生成图片的 URL
              // 显示图片
              var resultImage = document.getElementById('ID-show-demo-img');
              resultImage.src = imageUrl;
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
            layer.msg('请求失败，请重试', {icon: 2});
          });
        },'image/jpeg');


      });