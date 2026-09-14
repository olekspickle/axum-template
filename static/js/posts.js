var textArea = document.querySelector('textarea'),
post = document.getElementById('post'),
butWho = document.getElementById('who');

textArea.onfocus = function () {
    'use strict';

    if (textArea.getAttribute('placeholder') === "what's on your mind?") {
        textArea.setAttribute('placeholder', '');
    }
    post.style.background = 'rgba(0,0,0,0.6)';
};

textArea.onblur = function () {
    'use strict';
    if (textArea.getAttribute('placeholder') === '') {
        textArea.setAttribute('placeholder', "what's on your mind?");
    }
    post.style.background = 'rgba(0,0,0,0)';
};

// TODO: find excuse to integrate nats
//// just a simple script for nats fetch
//import { connect } from "https://deno.land/x/nats@v1.16.0/src/mod.ts";
//
//const servers = Deno.env.get("NATS_URL") || "nats://localhost:4222";
//const nc = await connect({
//servers: servers.split(","),
//});
//
//const sub_cfg = {callback: |(err, msg)| => {
//    if (err) {
//      console.log(err.message);
//    } else {
//      console.log(msg.data.string());
//}
//  },
//max: 5,
//};
//let sub = nc.subscribe("posts*", sub_cfg);
