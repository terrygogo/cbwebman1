webpackJsonp([11],{135:function(e,t,o){function r(e){o(482)}var a=o(51)(o(452),o(497),r,null,null);e.exports=a.exports},452:function(e,t,o){"use strict";Object.defineProperty(t,"__esModule",{value:!0});var r=o(1),a=o(34),i=o.n(a),n=o(481),l=(o.n(n),o(8));t.default={components:{QDataTable:l.E,QField:l.I,QInput:l.J,QCheckbox:l.D,QSelect:l.K,QSlider:l.L,QBtn:l.m,QIcon:l.q,QTooltip:l.d,QCollapsible:l.w,"vue-form-generator":i.a.component},beforeDestroy:function(){},data:function(){return{model:null,model2:[{make:"Ford",model:"jeep",year:2012}],schema:{fields:[{type:"input",inputType:"text",label:"ID",model:"id",readonly:!0,featured:!1,styleClasses:"half-width mandu",disabled:!0},{type:"input",inputType:"text",label:"Name",model:"name",styleClasses:"half-width mandu",readonly:!1,featured:!1,required:!0,disabled:!1,placeholder:"Users name",validator:i.a.validators.string},{type:"input",inputType:"password",label:"Password",model:"password",min:6,required:!0,hint:"Minimum 6 characters",styleClasses:"half-width",validator:i.a.validators.string},{type:"input",inputType:"number",label:"Age",model:"age",styleClasses:"half-width",min:18,validator:i.a.validators.number},{type:"input",inputType:"email",label:"E-mail",model:"email",placeholder:"Users e-mail address",styleClasses:"half-width goguma",validator:i.a.validators.email},{type:"checklist",label:"Skills",model:"skills",multi:!0,required:!0,multiSelect:!0,styleClasses:"half-width",values:["HTML5","Javascript","CSS3","CoffeeScript","AngularJS","ReactJS","VueJS"]},{type:"switch",label:"Status",model:"status",multi:!0,readonly:!1,featured:!1,disabled:!1,default:!0,styleClasses:"half-width",textOn:"Active",textOff:"Inactive"}]},formOptions:{validateAfterLoad:!0,validateAfterChanged:!0,fieldIdPrefix:"user-"},temp:{date:"2017-08-25",name:"terry",address:"seoul"},tableData3:[{date:"2016-05-03",name:"Tom",address:"No. 189, Grove St, Los Angeles"},{date:"2016-05-02",name:"Tom",address:"No. 189, Grove St, Los Angeles"},{date:"2016-05-04",name:"Tom",address:"No. 189, Grove St, Los Angeles"},{date:"2016-05-01",name:"Tom",address:"No. 189, Grove St, Los Angeles"},{date:"2016-05-08",name:"Tom",address:"No. 189, Grove St, Los Angeles"},{date:"2016-05-06",name:"Tom",address:"No. 189, Grove St, Los Angeles"},{date:"2016-05-07",name:"Tom",address:"No. 189, Grove St, Los Angeles"}],multipleSelection:[]}},methods:{toggleSelection:function(e){var t=this;e?e.forEach(function(e){t.$refs.multipleTable.toggleRowSelection(e)}):this.$refs.multipleTable.clearSelection()},addthis:function(){this.tableData3.unshift(this.temp)},delselection:function(){for(var e=0;e<this.multipleSelection.length;e++){var t=this.multipleSelection[e],o=this.tableData3.indexOf(t);this.tableData3.splice(o,1)}},handleSelectionChange:function(e){this.multipleSelection=e}},created:function(){r.default.axios.get("/json/vfg_model.json").then(function(e){this.model=e.data}.bind(this)).catch(function(e){console.log(e)})},mounted:function(){}}},466:function(e,t,o){t=e.exports=o(126)(void 0),t.push([e.i,'.vue-form-generator *{box-sizing:border-box}.vue-form-generator .form-control{display:block;padding:6px 12px;font-size:14px;line-height:1.42857143;color:#555;background-color:#fff;background-image:none;border:1px solid #ccc;border-radius:4px;box-shadow:inset 0 1px 1px rgba(0,0,0,.075);transition:border-color .15s ease-in-out,box-shadow .15s ease-in-out}.vue-form-generator .form-control:not([class*=" col-"]){width:100%}.vue-form-generator span.help{margin-left:.3em;position:relative}.vue-form-generator span.help .icon{display:inline-block;width:16px;height:14px;background-image:url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABmJLR0QA/wD/AP+gvaeTAAAA+UlEQVQ4ja3TS0oDQRAG4C8+lq7ceICICoLGK7iXuNBbeAMJuPVOIm7cqmDiIncIggg+cMZFaqCnZyYKWtB0df31V1VXdfNH6S2wD9CP8xT3KH8T9BiTcE7XBMOfyBcogvCFO9ziLWwFRosyV+QxthNsA9dJkEYlvazsQdi3sBv6Ol6TBLX+HWT3fcQZ3vGM5fBLk+ynAU41m1biCXvhs4OPBDuBpa6GxF0P8YAj3GA1d1qJfdoS4DOIcIm1DK9x8iaWeDF/SP3QU6zRROpjLDFLsFlibx1jJaMkSIGrWKntvItcyTBKzCcybsvc9ZmYz3kz9Ooz/b98A8yvW13B3ch6AAAAAElFTkSuQmCC");background-repeat:no-repeat;background-position:50%}.vue-form-generator span.help .helpText{background-color:#444;bottom:30px;color:#fff;display:block;left:0;opacity:0;padding:20px;pointer-events:none;position:absolute;text-align:justify;width:300px;transition:all .25s ease-out;box-shadow:2px 2px 6px rgba(0,0,0,.5);border-radius:6px}.vue-form-generator span.help .helpText a{font-weight:700;text-decoration:underline}.vue-form-generator span.help .helpText:before{bottom:-20px;content:" ";display:block;height:20px;left:0;position:absolute;width:100%}.vue-form-generator span.help:hover .helpText{opacity:1;pointer-events:auto;-webkit-transform:translateY(0);transform:translateY(0)}.vue-form-generator .field-wrap{display:-webkit-box;display:-ms-flexbox;display:flex}.vue-form-generator .field-wrap .buttons{white-space:nowrap;margin-left:4px}.vue-form-generator .field-wrap button,.vue-form-generator .field-wrap input[type=submit]{display:inline-block;padding:6px 12px;margin:0;font-size:14px;font-weight:400;line-height:1.42857143;text-align:center;white-space:nowrap;vertical-align:middle;-ms-touch-action:manipulation;touch-action:manipulation;cursor:pointer;-webkit-user-select:none;-moz-user-select:none;-ms-user-select:none;user-select:none;color:#333;background-color:#fff;border:1px solid #ccc;border-radius:4px}.vue-form-generator .field-wrap button:not(:last-child),.vue-form-generator .field-wrap input[type=submit]:not(:last-child){margin-right:4px}.vue-form-generator .field-wrap button:hover,.vue-form-generator .field-wrap input[type=submit]:hover{color:#333;background-color:#e6e6e6;border-color:#adadad}.vue-form-generator .field-wrap button:active,.vue-form-generator .field-wrap input[type=submit]:active{color:#333;background-color:#d4d4d4;border-color:#8c8c8c;outline:0;box-shadow:inset 0 3px 5px rgba(0,0,0,.125)}.vue-form-generator .field-wrap button:disabled,.vue-form-generator .field-wrap input[type=submit]:disabled{opacity:.6;cursor:not-allowed}.vue-form-generator .hint{font-style:italic;font-size:.8em}.vue-form-generator .form-group{display:inline-block;vertical-align:top;width:100%;margin-bottom:1rem}.vue-form-generator .form-group label{font-weight:400}.vue-form-generator .form-group.featured>label{font-weight:700}.vue-form-generator .form-group.required>label:after{content:"*";font-weight:400;color:red;padding-left:.2em;font-size:1em}.vue-form-generator .form-group.disabled>label{color:#666;font-style:italic}.vue-form-generator .form-group.error input:not([type=checkbox]),.vue-form-generator .form-group.error select,.vue-form-generator .form-group.error textarea{border:1px solid red;background-color:rgba(255,0,0,.15)}.vue-form-generator .form-group.error .errors{color:red;font-size:.8em}.vue-form-generator .form-group.error .errors span{display:block;background-image:url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAiklEQVR4Xt2TMQoCQQxF3xdhu72MpZU3GU/meBFLOztPYrVWsQmEWSaMsIXgK8P8RyYkMjO2sAN+K9gTIAmDAlzoUzE7p4IFytvDCQWJKSStYB2efcAvqZFM0BcstMx5naSDYFzfLhh/4SmRM+6Agw/xIX0tKEDFufeDNRUc4XqLRz3qabVIf3BMHwl6Ktexn3nmAAAAAElFTkSuQmCC");background-repeat:no-repeat;padding-left:17px;padding-top:0;margin-top:.2em;font-weight:600}.vue-form-generator .field-checkbox input{margin-left:12px}.vue-form-generator .field-checklist .dropList,.vue-form-generator .field-checklist .listbox{height:auto;max-height:150px;overflow:auto}.vue-form-generator .field-checklist .dropList .list-row label,.vue-form-generator .field-checklist .listbox .list-row label{font-weight:400}.vue-form-generator .field-checklist .dropList .list-row input,.vue-form-generator .field-checklist .listbox .list-row input{margin-right:.3em}.vue-form-generator .field-checklist .combobox{height:auto;overflow:hidden}.vue-form-generator .field-checklist .combobox .mainRow{cursor:pointer;position:relative;padding-right:10px}.vue-form-generator .field-checklist .combobox .mainRow .arrow{position:absolute;right:-9px;top:3px;width:16px;height:16px;-webkit-transform:rotate(0deg);transform:rotate(0deg);transition:-webkit-transform .5s;transition:transform .5s;transition:transform .5s,-webkit-transform .5s;background-image:url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAALEwAACxMBAJqcGAAAAGdJREFUOI3tzjsOwjAURNGDUqSgTxU5K2AVrJtswjUsgHSR0qdxAZZFPrS+3ZvRzBsqf9MUtBtazJk+oMe0VTriiZCFX8nbpENMgfARjsn74vKj5IFruhfc8d6zIF9S/Hyk5HS4spMVeFcOjszaOwMAAAAASUVORK5CYII=");background-repeat:no-repeat}.vue-form-generator .field-checklist .combobox .mainRow.expanded .arrow{-webkit-transform:rotate(-180deg);transform:rotate(-180deg)}.vue-form-generator .field-checklist .combobox .dropList{transition:height .5s}.vue-form-generator .field-input .wrapper,.vue-form-generator .field-input input[type=radio]{width:100%}.vue-form-generator .field-input input[type=color]{width:60px}.vue-form-generator .field-input input[type=range]{padding:0}.vue-form-generator .field-input .helper{margin:auto .5em}.vue-form-generator .field-label span{display:block;width:100%;margin-left:12px}.vue-form-generator .field-radios .radio-list label{display:block}.vue-form-generator .field-radios .radio-list label input[type=radio]{margin-right:5px}.vue-form-generator .field-submit input{color:#fff!important;background-color:#337ab7!important;border-color:#2e6da4!important}.vue-form-generator .field-image .wrapper{width:100%}.vue-form-generator .field-image .preview{position:relative;margin-top:5px;height:100px;background-repeat:no-repeat;background-size:contain;background-position:50%;border:1px solid #ccc;border-radius:3px;box-shadow:inset 0 1px 1px rgba(0,0,0,.075)}.vue-form-generator .field-image .preview .remove{background-image:url("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAXUlEQVR42u2SwQoAIAhD88vVLy8KBlaS0i1oJwP3piGVg0Skmpq8HjqZrWl9uwCbGAmwKYGZs/6iqgMyAdJuM8W2QmYKpLt/0AG9ASCv/oAnANd3AEjmAlFT1BypAV+PnRH5YehvAAAAAElFTkSuQmCC");width:16px;height:16px;font-size:1.2em;position:absolute;right:.2em;bottom:.2em;opacity:.7}.vue-form-generator .field-image .preview .remove:hover{opacity:1;cursor:pointer}.vue-form-generator .field-noUiSlider .field-wrap{display:block}.vue-form-generator .field-noUiSlider .contain-pips{margin-bottom:30px}.vue-form-generator .field-noUiSlider .contain-tooltip{margin-top:30px}.vue-form-generator .field-noUiSlider .noUi-vertical{height:200px;margin:10px 0}.vue-form-generator .field-rangeSlider .irs{width:100%}.vue-form-generator .field-selectEx .bootstrap-select .dropdown-menu li.selected .text{font-weight:700}.vue-form-generator .field-staticMap img{display:block;width:auto;max-width:100%}.vue-form-generator .field-switch .field-wrap label{position:relative;display:block;vertical-align:top;width:120px;height:30px;padding:0;margin:0 10px 10px 0;border-radius:15px;box-shadow:inset 0 -1px #fff,inset 0 1px 1px rgba(0,0,0,.05);cursor:pointer}.vue-form-generator .field-switch input{position:absolute;top:0;left:0;opacity:0}.vue-form-generator .field-switch .label{position:relative;display:block;height:inherit;font-size:10px;text-transform:uppercase;background:#eceeef;border-radius:inherit;box-shadow:inset 0 1px 2px rgba(0,0,0,.12),inset 0 0 2px rgba(0,0,0,.15)}.vue-form-generator .field-switch .label:after,.vue-form-generator .field-switch .label:before{position:absolute;top:50%;margin-top:-.5em;line-height:1;transition:inherit}.vue-form-generator .field-switch .label:before{content:attr(data-off);right:11px;color:#aaa;text-shadow:0 1px hsla(0,0%,100%,.5)}.vue-form-generator .field-switch .label:after{content:attr(data-on);left:11px;color:#fff;text-shadow:0 1px rgba(0,0,0,.2);opacity:0}.vue-form-generator .field-switch input:checked~.label{background:#e1b42b;box-shadow:inset 0 1px 2px rgba(0,0,0,.15),inset 0 0 3px rgba(0,0,0,.2)}.vue-form-generator .field-switch input:checked~.label:before{opacity:0}.vue-form-generator .field-switch input:checked~.label:after{opacity:1}.vue-form-generator .field-switch .handle{position:absolute;top:1px;left:1px;width:28px;height:28px;background:linear-gradient(180deg,#fff 40%,#f0f0f0);background-image:-webkit-linear-gradient(top,#fff 40%,#f0f0f0);border-radius:100%;box-shadow:1px 1px 5px rgba(0,0,0,.2)}.vue-form-generator .field-switch .handle:before{content:"";position:absolute;top:50%;left:50%;margin:-6px 0 0 -6px;width:12px;height:12px;background:linear-gradient(180deg,#eee,#fff);background-image:-webkit-linear-gradient(top,#eee,#fff);border-radius:6px;box-shadow:inset 0 1px rgba(0,0,0,.02)}.vue-form-generator .field-switch input:checked~.handle{left:91px;left:calc(100% - ($field-switch-height - 1px));box-shadow:-1px 1px 5px rgba(0,0,0,.2)}.vue-form-generator .field-switch .handle,.vue-form-generator .field-switch .label{transition:all .3s ease}',""])},467:function(e,t,o){t=e.exports=o(126)(void 0),t.push([e.i,"h3{font-size:16px}.el-table th{background-color:#bbdefb}.el-table th .cell{background-color:#90caf9}.vue-form-generator .form-group.half-width{width:20%}.vue-form-generator .form-group.mandu{width:50%}",""])},481:function(e,t,o){var r=o(466);"string"==typeof r&&(r=[[e.i,r,""]]),r.locals&&(e.exports=r.locals);o(127)("070c6e57",r,!0)},482:function(e,t,o){var r=o(467);"string"==typeof r&&(r=[[e.i,r,""]]),r.locals&&(e.exports=r.locals);o(127)("8f65967e",r,!0)},497:function(e,t){e.exports={render:function(){var e=this,t=e.$createElement,o=e._self._c||t;return o("div",{staticClass:"layout-padding"},[o("q-collapsible",{staticClass:"shadow-2",staticStyle:{"max-width":"100%","margin-bottom":"25px"},attrs:{opened:"",label:"Showcasing some of the options",sublabel:"Change them to see it in action"}},[o("el-table",{ref:"multipleTable",staticStyle:{width:"100%"},attrs:{data:e.tableData3,border:""},on:{"selection-change":e.handleSelectionChange}},[o("el-table-column",{attrs:{type:"selection",width:"55"}}),e._v(" "),o("el-table-column",{attrs:{label:"Date",width:"120"},scopedSlots:e._u([{key:"default",fn:function(t){return[e._v(e._s(t.row.date))]}}])}),e._v(" "),o("el-table-column",{attrs:{property:"name",label:"Name",width:"120"}}),e._v(" "),o("el-table-column",{attrs:{property:"address",label:"Address","show-overflow-tooltip":""}})],1),e._v(" "),o("div",{staticStyle:{"margin-top":"20px"}},[o("el-button",{on:{click:function(t){e.toggleSelection([e.tableData3[1],e.tableData3[2]])}}},[e._v("Toggle selection status of second and third rows")]),e._v(" "),o("el-button",{on:{click:function(t){e.toggleSelection()}}},[e._v("Clear selection")]),e._v(" "),o("el-button",{on:{click:function(t){e.addthis()}}},[e._v("add")]),e._v(" "),o("el-button",{on:{click:function(t){e.delselection()}}},[e._v("del")]),e._v(" "),o("vue-form-generator",{attrs:{schema:e.schema,model:e.model,options:e.formOptions}}),e._v(" "),o("div",{attrs:{id:"editor_holder"}}),e._v(" "),o("button",{attrs:{id:"submit"}},[e._v("puch!!! (console.log)")])],1)],1)],1)},staticRenderFns:[]}}});