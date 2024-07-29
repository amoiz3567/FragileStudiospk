document.addEventListener('scroll', (event) => {
    //this.style.display = 'flex';
    var header = document.getElementById('header');
    var fk = document.getElementById('fkhead');
    if (document.scrollingElement.scrollTop >= 368) {
        header.style.display = "flex";
        header.style.transition = "0.26s";
        setTimeout(() => {
            header.classList.add("frao");
            header.style.transform = "translate(0, -6%)";
            fk.style.display = "block"; 
            frg.style.margin = "0px";
            frg.style.marginTop = "";
            //frg.style.marginBottom = "20px";
            if (window.innerWidth <= 475) {
                console.log("yes this works now yay!");
                frg.style.marginBottom = "0";
            }
            frg.style.width = "140px";
            //frg.style.width = "10px";
            //setTimeout(() => header.style.transition ="0s", 50);
        }, 1);

    } else if (document.scrollingElement.scrollTop < 368) {
        if (window.innerWidth <= 475)
            header.style.transform = "translate(0, 20%)";
        else
        header.style.transform = "translate(0, 40%)";
        header.classList.remove("frao");
        fk.style.display = "none";
        header.style.opacity = "1";
        frg.style.margin = "0";
        if (window.innerWidth <= 475) {
            console.log("yes this works now yay!");
            frg.style.marginBottom = "15px";
        }
        frg.style.marginTop = "20px";
        frg.style.width = ""; //240px
    }
});
