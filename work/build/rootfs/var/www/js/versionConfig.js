!function(){var e=Page.versionConfig={init:function(){has_hide_download_webconfig?$("version_download_webconfig").style.display="none":$("version_download_webconfig").style.display="",has_hide_version_kernel&&($("version_kernel_label").style.display="none",$("version_kernel").style.display="none"),e.translate(),e.render()},translate:function(){$("version").set("text",tl("w_Edition Info")),$("version_kernel_label").set("text",tl("w_kernelVersion")),$("version_fs_label").set("text",tl("w_fsVersion")),$("version_web_label").set("text",tl("Web Version")),$("version_sn_label").set("text",tl("w_Serialnumber")),$("version_webconfig_label").set("text",tl("w_verWebconfig")),$("version_download_webconfig").set("text",tl("w_downloadWebconfig")),$("version_download_webconfig_span").set("text",tl("w_downloadWebconfig_CD")),hasWebConfigInCD?($("version_newWebconfigInfo").set("text",tl("w_newWebconfigInfo_CD")),$("version_download_webconfig").style.display="none",$("version_download_webconfig_span").style.display=""):$("version_newWebconfigInfo").set("text",tl("w_newWebconfigInfo"))},render:function(){var s,e,n='<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2001/12/soap-envelope"><soap:Header>\t<userid>'+g_des_userid+"</userid>\t<passwd>"+g_des_passwd+"</passwd></soap:Header><soap:Body></soap:Body></soap:Envelope>",n=(sendRequest(n,function(e){var e=xmlLoadText(e),n=[];try{(n=e?e.getElementsByTagName("WEBSITE"):n).length&&0!=(s=n[0].getAttribute("website_name4")+"").length&&$("version_download_webconfig").setAttribute("href","http://"+s)}catch(o){}},!0,"/getTestWebSiteConfigMsg",function(){}),'<?xml version="1.0"?><soap:Envelope xmlns:soap="http://www.w3.org/2001/12/soap-envelope"><soap:Header>\t<userid>'+g_des_userid+"</userid>\t<passwd>"+g_des_passwd+"</passwd></soap:Header><soap:Body></soap:Body></soap:Envelope>");sendRequest(n,function(e){var e=xmlLoadText(e),n=[];try{(n=e&&e.documentElement?e.documentElement.getElementsByTagName("VersionInfo"):n).length&&($("version_kernel").innerHTML=n[0].getAttribute("kernelVersion"),$("version_fs").innerHTML=n[0].getAttribute("fsVersion"),(n=e&&e.documentElement?e.documentElement.getElementsByTagName("SerialNumber"):n).length)&&($("version_sn").innerHTML=n[0].getAttribute("serialNumber"))}catch(o){}},!0,"/getSystemVersionInfo",function(){}),$("version_showNewWebconfigInfo").style.display="none",""!=g_curWebconfigVersion?4<=(n=(version_webconfig.innerHTML=g_curWebconfigVersion).split(".")).length&&(0,n=256*(256*(256*parseInt(n[0])+parseInt(n[1]))+parseInt(n[2]))+parseInt(n[3]),4<=(e=g_WebConfigVersion.split(".")).length)&&(0,n<(e=256*(256*(256*parseInt(e[0])+parseInt(e[1]))+parseInt(e[2]))+parseInt(e[3])))&&($("version_showNewWebconfigInfo").style.display=""):version_webconfig.innerHTML=tl("w_noVerWebconfig"),$("version_webconfig_container").style.display="none",ws_isok&&(version_webconfig.innerHTML=ws_version,ws_update_prompt)&&($("version_showNewWebconfigInfo").style.display="")},bind:function(){}}}();
/* ===== Hardware Diagnostics (added by custom HTTPS build) =================== */
(function(){
	var FIELDS=[
		["SoC / machine","machine"],
		["SoC id","soc_id"],
		["SoC family","soc_family"],
		["CPU info","cpuinfo"],
		["Kernel","kernel"],
		["Arch","arch"],
		["CPU cores","cpu_cores"],
		["CPU usage","cpu_usage"],
		["CPU jiffies","cpu_jiffies"],
		["Load avg","loadavg"],
		["Uptime","uptime"],
		["Mem total","mem_total"],
		["Mem free","mem_free"],
		["Mem avail","mem_avail"],
		["Mem used","mem_used_pct"],
		["Buffers+cache","mem_buffers_cached"],
		["Temperature","temperature"],
		["MAC","mac"],
		["IP addrs","ip_addrs"],
		["Default route","default_route"],
		["MTD devices","mtd_devices"],
		["RootFS","rootfs_dev"],
		["NAND mount","nand_mount"],
		["SD /mnt/mmc0","storage_mmc0"],
		["SD /mnt/mmc1","storage_mmc1"],
		["USB /mnt/usb","storage_usb"],
		["USB devices","usb_devices"],
		["Sensor","sensor"],
		["Processes","process_count"],
		["Top processes","top_processes"],
		["Sampled","generated"],
		["-- diagnostics --","_diag"],
		["pid","pid"],
		["PATH","path"],
		["date probe","date_probe"],
		["uname probe","uname_probe"],
		["busybox","busybox"],
		["cmd probe","cmd_probe"]
	];
	function esc(s){
		return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
	}
	function fmtUptime(raw){
		// "17099.06 119878.26" -> "4h 44m 59s"
		var p=String(raw||"").split(" ");
		var t=parseFloat(p[0]);
		if(isNaN(t))return raw||"n/a";
		var d=Math.floor(t/86400),h=Math.floor(t%86400/3600),m=Math.floor(t%3600/60),s=Math.floor(t%60);
		var out="";
		if(d)out+=d+"d ";
		if(d||h)out+=h+"h ";
		if(d||h||m)out+=m+"m ";
		out+=s+"s";
		return out;
	}
	function parse(t){
		try{ if(window.JSON&&JSON.parse)return JSON.parse(t); }catch(e){}
		try{ if(window.JSON&&JSON.decode)return JSON.decode(t); }catch(e){}
		return null;
	}
	function render(txt){
		var grid=$("hwinfo_grid"); if(!grid)return;
		var d=parse(txt);
		if(!d){
			var raw=String(txt==null?"(empty)":txt).replace(/</g,"&lt;");
			if(raw.length>400)raw=raw.substring(0,400)+"\u2026";
			grid.innerHTML='<span style="color:#c00">No valid data \u2014 hwinfo.sh may not be running.<br/>Raw response:</span><pre style="color:#666;margin:4px 0;white-space:pre-wrap;word-break:break-all">'+raw+'</pre>';
			return;
		}
		var rows="";
		for(var i=0;i<FIELDS.length;i++){
			var label=FIELDS[i][0], key=FIELDS[i][1];
			if(key==="_diag"){
				rows+='<div style="display:table-row"><span style="display:table-cell;padding:6px 0 2px;color:#333;font-weight:bold;border-top:1px solid #ddd;margin-top:6px">'+esc(label)+'</span></div>';
				continue;
			}
			var v=d[key];
			if(key==="uptime"&&v) v=fmtUptime(v);
			if(v===undefined||v===null||v==="") v="n/a";
			var dim=(v==="n/a"||v==="not mounted")?' style="color:#aaa"':'';
			rows+='<div style="display:table-row">'
				+'<span style="display:table-cell;padding:1px 12px 1px 0;color:#666;white-space:nowrap">'+esc(label)+'</span>'
				+'<span'+dim+' style="display:table-cell;white-space:pre-wrap;word-break:break-all">'+esc(v)+'</span>'
				+'</div>';
		}
		grid.innerHTML=rows;
		var st=$("hwinfo_status");
		if(st) st.innerHTML="updated "+esc(d.generated||"");
	}
	function load(){
		var st=$("hwinfo_status");
		if(st) st.innerHTML="refreshing&hellip;";
		try{
			new Request({url:"/hwinfo.txt?_="+(new Date().getTime()), async:true,
				onSuccess:function(t){ render(t); },
				onFailure:function(x){ var g=$("hwinfo_grid"); if(g)g.innerHTML='<span style="color:#c00">fetch failed: HTTP '+(x&&x.status)+' '+esc(x&&x.statusText||'')+'</span>'; }
			}).get();
		}catch(e){
			var g=$("hwinfo_grid"); if(g)g.innerHTML='<span style="color:#c00">request error: '+esc(e)+'</span>';
		}
	}
	window.hwinfoRefresh=load;
	// hook the page: after the stock render, pull hardware info
	try{
		if(window.Page&&Page.versionConfig&&Page.versionConfig.render){
			var _orig=Page.versionConfig.render;
			Page.versionConfig.render=function(){
				try{_orig.apply(this,arguments);}catch(e){}
				load();
			};
		}
	}catch(e){}
	// wire the refresh link once DOM ids exist
	try{
		var btn=$("hwinfo_refresh");
		if(btn&&!btn.__hw){ btn.__hw=1; btn.addEvent("click",load); }
	}catch(e){}
})();
