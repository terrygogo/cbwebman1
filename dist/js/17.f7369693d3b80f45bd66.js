webpackJsonp([17],{138:function(t,e,o){function i(t){o(445)}var a=o(51)(o(412),o(460),i,"data-v-7e3f86e3",null);t.exports=a.exports},412:function(t,e,o){"use strict";function i(t,e,o){var i=o>0?1:-1;return{roll:Math.atan2(e,i*Math.sqrt(Math.pow(o,2)+.001*Math.pow(t,2)))*s,pitch:-Math.atan2(t,Math.sqrt(Math.pow(e,2)+Math.pow(o,2)))*s}}Object.defineProperty(e,"__esModule",{value:!0});var a=o(8),n=a.O.viewport,r=a.P.position,s=180/Math.PI;e.default={name:"index",components:{QLayout:a.g,QToolbar:a.h,QTabs:a.i,QRouteTab:a.k,QToolbarTitle:a.l,QBtn:a.m,QIcon:a.q,QList:a.s,QListHeader:a.u,QSideLink:a.v,QCollapsible:a.w,QItem:a.x,QItemSide:a.y,QItemMain:a.A},data:function(){return{orienting:window.DeviceOrientationEvent&&!this.$q.platform.is.desktop,rotating:window.DeviceMotionEvent&&!this.$q.platform.is.desktop,moveX:0,moveY:0,rotateY:0,rotateX:0,competitions:[{id:"log",name:"어디로"},{id:"man",name:"그냥 어디로"}]}},computed:{position:function(){var t="rotateX("+this.rotateX+"deg) rotateY("+this.rotateY+"deg)";return{top:this.moveY+"px",left:this.moveX+"px","-webkit-transform":t,"-ms-transform":t,transform:t}}},methods:{launch:function(t){o.i(a.N)(t)},move:function(t){var e=n(),o=e.width,i=e.height,a=r(t),s=a.top,l=a.left,c=i/2,m=o/2;this.moveX=(l-m)/m*-30,this.moveY=(s-c)/c*-30,this.rotateY=l/o*40*2-40,this.rotateX=-(s/i*40*2-40)},rotate:function(t){if(t.rotationRate&&null!==t.rotationRate.beta&&null!==t.rotationRate.gamma)this.rotateX=.7*t.rotationRate.beta,this.rotateY=-.7*t.rotationRate.gamma;else{var e=t.acceleration.x||t.accelerationIncludingGravity.x,o=t.acceleration.y||t.accelerationIncludingGravity.y,a=t.acceleration.z||t.accelerationIncludingGravity.z-9.81,n=i(e,o,a);this.rotateX=.7*n.roll,this.rotateY=-.7*n.pitch}},orient:function(t){null===t.beta||null===t.gamma?(window.removeEventListener("deviceorientation",this.orient,!1),this.orienting=!1,window.addEventListener("devicemotion",this.rotate,!1)):(this.rotateX=.7*t.beta,this.rotateY=-.7*t.gamma)}},mounted:function(){var t=this;this.$nextTick(function(){t.orienting?window.addEventListener("deviceorientation",t.orient,!1):t.rotating?window.addEventListener("devicemove",t.rotate,!1):document.addEventListener("mousemove",t.move)})},beforeDestroy:function(){this.orienting?window.removeEventListener("deviceorientation",this.orient,!1):this.rotating?window.removeEventListener("devicemove",this.rotate,!1):document.removeEventListener("mousemove",this.move)}}},430:function(t,e,o){e=t.exports=o(126)(void 0),e.push([t.i,".router-link-active[data-v-7e3f86e3]{color:#027be3;background-color:#f0f0f0!important;border-right:4px solid lime-4;border-left:4px solid #027be3}.router-link-active .item-primary[data-v-7e3f86e3]{color:#027be3}.q-tabs[data-v-7e3f86e3]{color:green}",""])},445:function(t,e,o){var i=o(430);"string"==typeof i&&(i=[[t.i,i,""]]),i.locals&&(t.exports=i.locals);o(127)("4d5a86a7",i,!0)},460:function(t,e){t.exports={render:function(){var t=this,e=t.$createElement,o=t._self._c||e;return o("q-layout",{ref:"layout",attrs:{view:"hHr LpR fff","left-class":{"bg-grey-2":!0}}},[o("q-toolbar",{staticClass:"glossy",slot:"header"},[o("q-toolbar-title",[t._v("\n      CoreBridge Manager \n      "),o("div",{slot:"subtitle"},[t._v("Running on v"+t._s(t.$q.version))])]),t._v(" "),o("q-btn",{attrs:{flat:""},on:{click:function(e){t.$refs.layout.toggleLeft()}}},[o("q-icon",{attrs:{name:"menu"}})],1)],1),t._v(" "),o("q-tabs",{slot:"navigation"},[o("q-route-tab",{attrs:{icon:"view_quilt",to:"/layout/about",replace:"",hide:"icon",label:"About"},slot:"title"}),t._v(" "),o("q-route-tab",{attrs:{icon:"view_day",to:"/layout/toolbar",replace:"",hide:"icon",label:"Toolbar"},slot:"title"}),t._v(" "),o("q-route-tab",{attrs:{icon:"view_day",to:"/layout/tabs",replace:"",label:"Tabs"},slot:"title"}),t._v(" "),o("q-route-tab",{attrs:{icon:"input",to:"/layout/drawer",replace:"",label:"Drawer"},slot:"title"})],1),t._v(" "),o("div",{slot:"left"},[o("q-list",{attrs:{"no-border":"",link:"","inset-delimiter":""}},[o("q-list-header",[t._v("Essential Links")]),t._v(" "),o("q-side-link",{attrs:{item:"",to:"/config"}},[o("q-item-side",{attrs:{icon:"school"}}),t._v(" "),o("q-item-main",{attrs:{label:"Toolbar"}})],1)],1),t._v(" "),o("q-collapsible",{attrs:{indent:"",icon:"event",label:"Event",opened:""}},[o("q-side-link",{attrs:{item:"",to:"/dashboard"}},[o("q-item-main",{attrs:{label:"CoreBridge"}})],1),t._v(" "),o("q-collapsible",{attrs:{menu:"",label:"Competitions",opened:""}},[o("div",{staticClass:"scroll",staticStyle:{"max-height":"400px"}},t._l(t.competitions,function(t){return o("q-side-link",{key:t,attrs:{item:"",to:""+t.id,exact:""}},[o("q-item-main",{attrs:{label:t.name}})],1)}))]),t._v(" "),o("q-side-link",{attrs:{item:"",to:"/app/other-info"}},[o("q-item-main",{attrs:{label:"Other Information"}})],1)],1),t._v(" "),o("q-list",{attrs:{"no-border":"",link:"","inset-delimiter":""}},[o("q-list-header",[t._v("Essential Links")]),t._v(" "),o("q-item",{on:{click:function(e){t.launch("http://quasar-framework.org")}}},[o("q-item-side",{attrs:{icon:"school"}}),t._v(" "),o("q-item-main",{attrs:{label:"Docs",sublabel:"quasar-framework.org"}})],1),t._v(" "),o("q-item",{on:{click:function(e){t.launch("http://forum.quasar-framework.org")}}},[o("q-item-side",{attrs:{icon:"record_voice_over"}}),t._v(" "),o("q-item-main",{attrs:{label:"Forum",sublabel:"forum.quasar-framework.org"}})],1),t._v(" "),o("q-item",{on:{click:function(e){t.launch("https://gitter.im/quasarframework/Lobby")}}},[o("q-item-side",{attrs:{icon:"chat"}}),t._v(" "),o("q-item-main",{attrs:{label:"Gitter Channel",sublabel:"Quasar Lobby"}})],1),t._v(" "),o("q-item",{on:{click:function(e){t.launch("https://twitter.com/quasarframework")}}},[o("q-item-side",{attrs:{icon:"rss feed"}}),t._v(" "),o("q-item-main",{attrs:{label:"Twitter",sublabel:"@quasarframework"}})],1)],1)],1),t._v(" "),o("router-view"),t._v(" "),o("q-toolbar",{staticClass:"glossy",staticStyle:{height:"30px"},attrs:{height:"240px"},slot:"footer"},[o("q-btn",{attrs:{flat:""},on:{click:function(e){t.$refs.layout.toggleLeft()}}},[o("q-icon",{attrs:{name:"menu"}})],1),t._v(" "),o("q-toolbar-title",[o("div",{slot:"subtitle"},[t._v("JionLab Co.,LTD 2017")])])],1)],1)},staticRenderFns:[]}}});