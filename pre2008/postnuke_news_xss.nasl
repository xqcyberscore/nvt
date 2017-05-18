# OpenVAS Vulnerability Test
# $Id: postnuke_news_xss.nasl 6040 2017-04-27 09:02:38Z teissa $
# Description: Post-Nuke News module XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

tag_summary = "The remote host is running a version of Post-Nuke which contains
  the 'News' module which itself is vulnerable to a cross site
  scripting issue.
  An attacker may use these flaws to steal the cookies of the
  legitimate users of this web site.";

tag_solution = "Upgrade to the latest version of postnuke";

#  Ref: Muhammad Faisal Rauf Danka   <mfrd@attitudex.com> - Gem Internet Services (Pvt) Ltd.

if(description)
{
  script_id(14727);
  script_version("$Revision: 6040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(5809);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Post-Nuke News module XSS");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_dependencies("secpod_zikula_detect.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){
  exit(0);
}

postVer =get_kb_item("www/" + port + "/postnuke");
if(!postVer){
  exit(0);
}

postVer = eregmatch(pattern:"(.*) under (.*)", string:postVer);
if(phpVer[1] == NULL && phpVer[2] == NULL){
   exit(0);
}

version=phpVer[1];
dir = phpVer[2];

if(!safe_checks())
{
  req = http_get(item:string(dir, "/modules.php?op=modload&name=News&file=article&sid=<script>foo</script>"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(res == NULL ){
   exit(0);
  }
  if(res =~ "HTTP/1\.. 200" && "<script>foo</script>" >< res){
  security_message(port);
  }
}

if(version_is_less_equal(version:version,test_version:"0.721")){
   security_message(port);
}
