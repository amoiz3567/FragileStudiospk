document.addEventListener('scroll', (event) => {
    //this.style.display = 'flex';
    var header = document.getElementById('header');
    var fk = document.getElementById('fkhead');
    if (document.scrollingElement.scrollTop >= 368) {
        header.style.display = "flex";
        header.style.transition = "0.26s";
        setTimeout(() => {
            header.classList.add("frao");
            header.style.transform = "translate(0, 0%)";
            fk.style.display = "block";
            frg.style.margin = "0px";
            frg.style.marginTop = "10px";
            //frg.style.marginBottom = "20px";
            frg.style.width = "140px";
            //frg.style.width = "10px";
            //setTimeout(() => header.style.transition ="0s", 50);
        }, 1);

    } else if (document.scrollingElement.scrollTop < 368) {
        header.style.transform = "translate(0, 50%)";
        header.classList.remove("frao");
        fk.style.display = "none";
        header.style.opacity = "1";
        frg.style.margin = "0";
        frg.style.marginTop = "20px";
        frg.style.width = "70px"; //240px
    }
});
