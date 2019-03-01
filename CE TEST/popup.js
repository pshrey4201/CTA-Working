
document.addEventListener('DOMContentLoaded', function() {
  var sendbutton = document.getElementById('send');
  // var socket;
  sendbutton.addEventListener('click', function() {
    var x = document.getElementById('myText').value;
    // socket = io.connect('http://' + x + ':' + 5000);
    chrome.runtime.sendMessage({
      msg: "sendUrl",
      data: {
          url: x
      }
    });
    console.log("hi");
    sendbutton.parentNode.removeChild(sendbutton);
    // socket.on('connect', function() {
    //     socket.emit('my event', 'I\'m connected!');
    //     console.log("hwllo");
    // });

  });
//   chrome.runtime.onMessage.addListener(
//     function(request, sender, sendResponse) {
//         if (request.msg === "downloadUrl") {
//             //  To do something
//             socket.emit('url', request.data.url)
//             console.log(request.data.url)
//             // console.log(request.data.content)
//         }
//     }
// );
});
