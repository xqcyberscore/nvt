###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nmap_http_enum.nasl 4716 2016-12-08 12:42:15Z cfi $
#
# Wrapper for Nmap HTTP Enum NSE script
#
# Authors:
# NSE-Script: Ron Bowes, Andrew Orr and  Rob Nicholls
# NASL-Wrapper: Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# NSE-Script: Copyright (c) The Nmap Security Scanner (http://nmap.org)
# NASL-Wrapper: Copyright (c) 2010 Greenbone Networks GmbH (http://www.greenbone.net)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "This script attempts to enumerate directories used by popular web
  applications and servers.

  This is a wrapper on the Nmap Security Scanner's (http://nmap.org) http-enum.nse.";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801265");
  script_version("$Revision: 4716 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-08 13:42:15 +0100 (Thu, 08 Dec 2016) $");
  script_tag(name:"creation_date", value:"2010-09-08 13:20:44 +0200 (Wed, 08 Sep 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Nmap NSE: HTTP Enum");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");
  script_add_preference(name: "displayall :", value: "no",type: "checkbox");
  script_add_preference(name: "variations :", value: "no",type: "checkbox");
  script_add_preference(name: "path :", value: "",type: "entry");
  script_add_preference(name: "limit :", value: "",type: "entry");
  script_add_preference(name: "fingerprints :", value: "",type: "entry");
  script_add_preference(name: "http-max-cache-size :", value: "",type: "entry");
  script_add_preference(name: "http.useragent :", value: "",type: "entry");
  script_add_preference(name: "pipeline :", value: "",type: "entry");

  script_add_preference(name: "http-enum.basepath :", value: "",type: "entry");
  script_add_preference(name: "http-enum.displayall :", value: "no",type: "checkbox");
  script_add_preference(name: "http-enum.fingerprintfile :", value: "",type: "entry");
  script_add_preference(name: "http-enum.category :", value: "",type: "entry");

  script_dependencies("toolcheck.nasl", "find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_mandatory_keys("Tools/Present/nmap", "Tools/Launch/nmap_nse");
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include ("http_func.inc");

## Check for Required Keys
if((! get_kb_item("Tools/Present/nmap5.21") &&
   ! get_kb_item("Tools/Present/nmap5.51")) ||
   ! get_kb_item("Tools/Launch/nmap_nse")) {
 exit(0);
}

## Get HTTP Ports
port = get_http_port(default:80);
if(!port){
  exit(0);
}

argv = make_list("nmap", "--script=http-enum.nse", "-p", port,
                  get_host_ip());

## Get the preferences
i = 0;

if( "yes" == script_get_preference("displayall :")){
  args[i++] = "displayall=1";
}

if( "yes" == script_get_preference("variations :")){
  args[i++] = "variations=1";
}

if( pref = script_get_preference("path :")){
  args[i++] = "path="+pref;
}

if( pref = script_get_preference("limit :")){
  args[i++] = "limit="+pref;
}

if( pref = script_get_preference("fingerprints :")){
  args[i++] = "fingerprints="+pref;
}

if( pref = script_get_preference("http-max-cache-size :")){
  args[i++] = "http-max-cache-size="+pref;
}

if( pref = script_get_preference("http.useragent :")){
  args[i++] = "http.useragent="+pref;
}

if( pref = script_get_preference("pipeline :")){
  args[i++] = "pipeline="+pref;
}

if (get_kb_item("Tools/Present/nmap5.51")){
  if( pref = script_get_preference("http-enum.basepath :")){
    args[i++] = "http-enum.basepath="+pref;
  }
  
  if( "yes" == script_get_preference("http-enum.displayall :")){
    args[i++] = "http-enum.displayall=1";
  }
  
  if( pref = script_get_preference("http-enum.fingerprintfile :")){
    args[i++] = "http-enum.fingerprintfile="+pref;
  }
  
  if( pref = script_get_preference("http-enum.category :")){
    args[i++] = "http-enum.category="+pref;
  }
}

if (i>0)
{
  scriptArgs= "--script-args=";
  foreach arg(args) {
    scriptArgs += arg + ",";
  }
  argv = make_list(argv,scriptArgs);
}

## Run nmap and Get the result
res = pread(cmd: "nmap", argv: argv);

if(res)
{
  foreach line (split(res))
  {
    if(ereg(pattern:"^\|",string:line)) {
      result +=  substr(chomp(line),2) + '\n';
    }

    error = eregmatch(string:line, pattern:"^nmap: (.*)$");
    if (error) {
      msg = string('Nmap command failed with following error message:\n', line);
      log_message(data : msg, port:port);
    }
  }

  if("http-enum" >< result) {
    msg = string('Result found by Nmap Security Scanner (http-enum.nse) ',
                'http://nmap.org:\n\n', result);
    security_message(data : msg, port:port);
  }
}
else
{
  msg = string('Nmap command failed entirely:\n');
  log_message(data : msg, port:port);
}
