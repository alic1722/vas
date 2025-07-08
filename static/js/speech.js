function speak(text) {
    if ('speechSynthesis' in window) {
        var utterance = new SpeechSynthesisUtterance(text);
        utterance.lang = 'zh-CN'; // 设置语言为中文
        speechSynthesis.speak(utterance);
    } else {
        console.error('浏览器不支持语音合成');
    }
}

function announceDetectedObjects(objects) {
    if (objects && objects.length > 0) {
        let message = '检测到以下物体：';
        objects.forEach((obj, index) => {
            message += obj.name;
            if (index < objects.length - 1) {
                message += '，';
            }
        });
        speak(message);
    } else {
        speak('未检测到任何物体');
    }
}