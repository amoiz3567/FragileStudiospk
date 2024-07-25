//! FUNKY MOUSE CURSOR POINTER THINGY
function routPointer() {
    var  a = document.querySelectorAll('.abs');
    a.forEach(function (e) {
        e.addEventListener('mouseover', function (e){
            document.getElementById('btnpointer').classList.add('abys');
        });
        e.addEventListener('mouseout', function (e){
            document.getElementById('btnpointer').classList.remove('abys');
        });
    });
        era = document.querySelectorAll('.bh');
        era.forEach(function (ev) {
        ev.addEventListener('mouseover', function (ev){
            document.getElementById('btnpointer').classList.remove('abys');
            document.getElementById('btnpointer').classList.add('bi');
        });
        ev.addEventListener('mouseout', function (ev){
            document.getElementById('btnpointer').classList.remove('bi');
        });
    });
}

var global_num_length = 0;

//! POINTER
function pointer_() {
    $(document).on("click mousemove","html",function(e){
    var x = e.clientX;
    var y = e.clientY;
    var newposX = x - (document.getElementById("btnpointer").clientWidth/2);
    var newposY = y - (document.getElementById("btnpointer").clientHeight/2);
    $(".btnpointer").css("transform","translate3d("+newposX+"px,"+newposY+"px,0px)");
    });
}

//! SIMPLEST AVERAGE (a+b+c)/3
function averageColor(imageElement) {
    var canvas
        = document.createElement('canvas'),
        context
            = canvas.getContext &&
            canvas.getContext('2d'),
        imgData, width, height,
        length,
        rgb = { r: 0, g: 0, b: 0 },
        count = 0;
    height = canvas.height =
        imageElement.naturalHeight ||
        imageElement.offsetHeight ||
        imageElement.height;
    width = canvas.width =
        imageElement.naturalWidth ||
        imageElement.offsetWidth ||
        imageElement.width;

    context.drawImage(imageElement, 0, 0);
    imgData = context.getImageData(0, 0, width, height);
    length = imgData.data.length;

    /*for (var i = 0; i < length; i += 4) {
        rgb.r += imgData.data[i];
        rgb.g += imgData.data[i + 1];
        rgb.b += imgData.data[i + 2];
        count++;
    }
    rgb.r
        = Math.floor(rgb.r / count);
    rgb.g
        = Math.floor(rgb.g / count);
    rgb.b
        = Math.floor(rgb.b / count);
    
    rgb.r
        = Math.floor(imgData.data[4]);
    rgb.g
        = Math.floor(imgData.data[5]);
    rgb.b
        = Math.floor(imgData.data[6]);
        *
    return rgb;*/
    for (let x = 0; x < canvas.width; x++) {
        edges.push(getGrayscaleValue(imageData, x, 0, canvas.width));
        edges.push(getGrayscaleValue(imageData, x, canvas.height - 1, canvas.width));
    }
    for (let y = 0; y < canvas.height; y++) {
        edges.push(getGrayscaleValue(imageData, 0, y, canvas.width));
        edges.push(getGrayscaleValue(imageData, canvas.width - 1, y, canvas.width));
    }

    // Determine the most frequent color
    const colorFrequency = {};
    edges.forEach(color => {
        const key = color.join(',');
        colorFrequency[key] = (colorFrequency[key] || 0) + 1;
    });

    const mostFrequentColor = Object.keys(colorFrequency).reduce((a, b) => colorFrequency[a] > colorFrequency[b] ? a : b);

    return `rgb(${mostFrequentColor})`;
}
function getGrayscaleValue(imageData, x, y, width) {
    const index = (y * width + x) * 4;
    const r = imageData[index];
    const g = imageData[index + 1];
    const b = imageData[index + 2];
    const grayscale = Math.round((r + g + b) / 3);
    return grayscale;
}

var rgb;
/*setTimeout(() => {
    rgb = averageColor(document.getElementById('img'));
    document.getElementById("block").style.backgroundColor ='rgb(' + rgb.r + ','+ rgb.g + ','+ rgb.b + ')';*
}, 500)*/


//! PRODUCT COUNTER (sloppiest code ever)
function ric(a) {
    let num = localStorage.getItem("counter", '1');
    document.getElementById("quantity").textContent = num;
    if (num < 1 || num > a) {
        num = 1;
        document.getElementById("quantity").textContent = num;
    }
    document.getElementById('up').addEventListener('click', function () {
        if (num != a) {
        document.getElementById("quantity").textContent = ++num;
        localStorage.setItem("counter", document.getElementById("nums").textContent);
        }
    });
    document.getElementById('down').addEventListener('click', function () {
        if (num != 1) {
        document.getElementById("quantity").textContent = --num;
        localStorage.setItem("counter", document.getElementById("nums").textContent);
        }
    });
}

//! MENU
function op(id="menu", id2="menu_", time=100) {
    const a = document.getElementById(id);
    const b = document.getElementById(id2);
    a.style.marginLeft = '-50%';
    setTimeout(function(){
        b.style.display = "none";
        a.style.display = 'none';
    }, time);
}
function menu(id="menu", id2="menu_", display= "block") {
    const a = document.getElementById(id);
    const b = document.getElementById(id2);
    //document.getElementById("menu").style.boxShadow = "0 0 1050px #00000046";
    a.style.display = display;
    a.style.opacity = "0";
    b.style.display = "flex";
    setTimeout(function() {
        a.style.marginLeft = "0";
        a.style.opacity = "1";
    }, 100);
    if (id != "menu") {
        var yes = document.getElementById(id).getElementsByClassName("yes_")[0];
        return yes;
    }
}

//! FIRST TICKER
setTimeout(function() {
    var ticker = document.getElementById('ticker');
    var tickerWidth = ticker.offsetWidth;
    var containerWidth = ticker.parentElement.offsetWidth;
    var animationDuration = tickerWidth / containerWidth * 10 + 's';
    ticker.style.animationDuration = animationDuration;
}, 200);


//! SECOND TICKER
function second_ticker(color='#0000009d') {
    var ticker2 = document.getElementById('ticker2');
    window.addEventListener("load", (event) => {
    for (let i = 0; i< 15; i++)
    ticker2.innerHTML += `<span><b class="thic" style="font-size: 20VW; writing-mode:horizontal-tb; color: ${color};">FRAGILE&nbsp;&nbsp;&nbsp&nbsp;&nbsp;&nbsp</b>&nbsp;&nbsp;&nbsp;<b class="thic" style="font-size: 5vw;writing-mode:vertical-lr; color:#999999;">&nbsp;</b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>`
    ticker2.style.animationPlayState = "paused";
    setTimeout(function () {
    ticker2.style.animationPlayState = "running";
    }, 500);
    });

    var tickerWidth_ = ticker2.offsetWidth;
    var containerWidth_ = ticker2.parentElement.offsetWidth;
    var animationDuration_ = tickerWidth_ / containerWidth_ * 10 + 's';
    ticker2.style.animationDuration = animationDuration_;
}
function getcookie(name) {
    const a =(decodeURIComponent(document.cookie)).toString().split(`;`);
    for (i = 0; i< a.length; i++) {
        b = a[i].split(`${name}=`);
        if (b[0].replace(/ /g, '') == '') {
            return (b[1]);
        }
    }
    return null
}
function cartR() {
    if (getcookie("id") == undefined || window.innerWidth <=574) {
        window.location.href = "/cart";
        return;
    }
    if (window.innerWidth >= 348)
    menu('cart', 'cart_', 'flex');
}

function respective(th) {
    window.location.href = `/doc#${th.innerText}`;
}



function setInputFilter(textbox, inputFilter, errMsg) {
    [ "input", "keydown", "keyup", "mousedown", "mouseup", "select", "contextmenu", "drop", "focusout" ].forEach(function(event) {
      textbox.addEventListener(event, function(e) {
        if (inputFilter(this.value)) {
          // Accepted value.
          if ([ "keydown", "mousedown", "focusout" ].indexOf(e.type) >= 0){
            this.classList.remove("input-error");
            this.setCustomValidity("");
          }
          this.oldValue = this.value;
          this.oldSelectionStart = this.selectionStart;
          this.oldSelectionEnd = this.selectionEnd;
        }
        else if (this.hasOwnProperty("oldValue")) {
          // Rejected value: restore the previous one.
          this.classList.add("input-error");
          this.setCustomValidity(errMsg);
          this.reportValidity();
          this.value = this.oldValue;
          this.setSelectionRange(this.oldSelectionStart, this.oldSelectionEnd);
        }
        else {
          // Rejected value: nothing to restore.
          this.value = "";
        }
      });
    });
  }