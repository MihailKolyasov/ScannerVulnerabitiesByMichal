var subBtn = document.querySelector('#subdomain');
var xssBtn = document.querySelector('#xss');
var sqlBtn = document.querySelector('#sql');
var ssrfBtn = document.querySelector('#ssrf');
var depth = 1;
var select  = document.querySelector("select");

select.addEventListener('change', () => {
    depth = select.value;
})

getPage();


function getPage(){
    browser.tabs.query({currentWindow: true, active: true}).then((tabs) => {
        var header = document.createElement('h4');
        header.setAttribute('class', "sub-title");
        var url = new URL(tabs[0].url);
        header.textContent = url;
        var div = document.querySelector(".header-url");
        div.appendChild(header);
        var request =  " [1]" + url.hostname;
        let sending = browser.runtime.sendNativeMessage(
            "ping_pong",
            request);
        sending.then(onResponseIp, onError);
    })
}

function onResponseIp(response) {
    console.log("ip");
    console.log(response);
    var header = document.createElement('h4');
    header.setAttribute('class', "sub-title");
    header.textContent = "IP: " + response;
    var div = document.querySelector(".header-ip");
    div.appendChild(header);
}


subBtn.addEventListener('click', outputSubdomains);
xssBtn.addEventListener('click', outputTestXSS);
sqlBtn.addEventListener('click', outputTestSQL);
ssrfBtn.addEventListener('click', outputTestSSRF);

function outputSubdomains(){
    subBtn.setAttribute("disabled", "true");
    browser.tabs.query({currentWindow: true, active: true}).then((tabs) => {
        var url = new URL(tabs[0].url);
        console.log("ping");
        let hostname = url.hostname;
        let hostnames = hostname.split(".");
        if (hostnames.length > 2)
        {
            hostname = hostnames[hostnames.length - 2] + "." + hostnames[hostnames.length - 1];
        }
        var request = " [2]" + hostname;
        let sending = browser.runtime.sendNativeMessage(
            "ping_pong",
            request);
        sending.then(onResponseSubdomains, onError);
    })
}

function onResponseSubdomains(response) {
    let currentDiv = document.querySelector(".list-subdomains");
    if (response == "pong3") {
        console.log("Received " + response);
        let p = document.createElement("p");
        p.textContent = "No subdomain found, try to increase the dictionary.";
        p.setAttribute('class', "title-block");
        currentDiv.appendChild(p);
    }
    else {
        let ul = document.createElement('ul');
        ul.setAttribute("class", "push")
        var data = JSON.parse(response);
        console.log(data['subdomains']);
        for (var key in data['subdomains'])
        {
            let li = document.createElement("li");
            li.textContent = data['subdomains'][key];
            ul.appendChild(li);
        }
        currentDiv.appendChild(ul);
    }
    subBtn.setAttribute("disabled", "false");
}

function outputTestXSS(){
    xssBtn.setAttribute("disabled", "true");
    browser.tabs.query({currentWindow: true, active: true}).then((tabs) => {
        var url = new URL(tabs[0].url);
        console.log(depth);
        var request = depth + "[3]" + url.href;
        let sending = browser.runtime.sendNativeMessage(
            "ping_pong",
            request);
        sending.then(onResponseTestXSS, onError);
    })
}

function onResponseTestXSS(response) {
    let currentDiv = document.querySelector(".xss-block");
    if (response == "pong3") {
        console.log("Received " + response);
        let p = document.createElement("p");
        p.textContent = "XSS vulnerability test did not detect any threats.";
        p.setAttribute('class', "title-block");
        currentDiv.appendChild(p);
    }
    else {
        let ul = document.createElement('ul');
        ul.setAttribute("class", "push")
        var data = JSON.parse(response);
        console.log(data['urls']);
        for (var key in data['urls'])
        {
            let li = document.createElement("li");
            li.textContent = data['urls'][key];
            ul.appendChild(li);
        }
        currentDiv.appendChild(ul);
    }
    subBtn.setAttribute("disabled", "false");
}


function outputTestSQL(){
    sqlBtn.setAttribute("disabled", "true");
    browser.tabs.query({currentWindow: true, active: true}).then((tabs) => {
        var url = new URL(tabs[0].url);
        console.log("ping");
        var request = depth + "[4]" + url.href;
        let sending = browser.runtime.sendNativeMessage(
            "ping_pong",
            request);
        sending.then(onResponseTestSQL, onError);
    })
}

function onResponseTestSQL(response) {
    let currentDiv = document.querySelector(".sql-block");
    if (response == "pong3") {
        console.log("Received " + response);
        let p = document.createElement("p");
        p.textContent = "SQL vulnerability test did not detect any threats.";
        p.setAttribute('class', "title-block");
        currentDiv.appendChild(p);
    }
    else {
        let ul = document.createElement('ul');
        ul.setAttribute("class", "push")
        var data = JSON.parse(response);
        console.log(data['urls']);
        for (var key in data['urls'])
        {
            let li = document.createElement("li");
            li.textContent = data['urls'][key];
            ul.appendChild(li);
        }
        currentDiv.appendChild(ul);
    }
    subBtn.setAttribute("disabled", "false");
}


function outputTestSSRF(){
    ssrfBtn.setAttribute("disabled", "true");
    browser.tabs.query({currentWindow: true, active: true}).then((tabs) => {
        var url = new URL(tabs[0].url);
        console.log("ping");
        var request = depth + "[5]" + url.href;
        let sending = browser.runtime.sendNativeMessage(
            "ping_pong",
            request);
        sending.then(onResponseTestSSRF, onError);
    })
}

function onResponseTestSSRF(response) {
    let currentDiv = document.querySelector(".ssrf-block");
    if (response == "pong3") {
        console.log("Received " + response);
        let p = document.createElement("p");
        p.textContent = "SSRF vulnerability test did not detect any threats."
        p.setAttribute('class', "title-block");
        currentDiv.appendChild(p);
    }
    else {
        let ul = document.createElement('ul');
        ul.setAttribute("class", "push")
        var data = JSON.parse(response);
        console.log(data['urls']);
        for (var key in data['urls'])
        {
            let li = document.createElement("li");
            li.textContent = data['urls'][key];
            ul.appendChild(li);
        }
        currentDiv.appendChild(ul);
    }
    subBtn.setAttribute("disabled", "false");
}

function onResponse(response) {
    
    if (response == "pong3")
        console.log("Received " + response);
    else {
        var data = JSON.parse(response);
        console.log(data);    
    }
}

function onError(error) {
    console.log(`Error: ${error}`);
}

