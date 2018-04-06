##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpgenealogie_rfi_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# PHPGenealogie 'CoupleDB.php' Remote File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
code on the vulnerable Web server.

Impact level: Application/System";

tag_affected = "PHPGenealogie version 2.0";

tag_insight = "The flaw is due to error in 'DataDirectory' parameter in
'CoupleDB.php' which is not properly verified before being used to includefiles.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running PHPGenealogie and is prone to Remote File
Inclusion vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801008");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3541");
  script_name("PHPGenealogie 'CoupleDB.php' Remote File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9155");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51728");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phpgenealogie_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

phpgenPort = get_http_port(default:80);
if(!phpgenPort){
  exit(0);
}

phpgenVer = get_kb_item("www/" + phpgenPort + "/PHPGenealogie");
phpgenVer = eregmatch(pattern:"^(.+) under (/.*)$", string:phpgenVer);

if((phpgenVer[2] != NULL) && (!safe_checks()))
{
  sndReq = http_get(item:string(phpgenVer[2], "/CoupleDB.php?Parametre=0&" +
                         "DataDirectory=xyz/OpenVAS-RemoteFileInclusion.txt"),
                    port:phpgenPort);
  rcvRes = http_send_recv(port:phpgenPort, data:sndReq);
  if("xyz/OpenVAS-RemoteFileInclusion.txt" >< rcvRes)
  {
    security_message(phpgenPort);
    exit(0);
  }
}
else
{
  if(phpgenVer[1] != NULL)
  {
    if(version_is_equal(version:phpgenVer[1], test_version:"2.0")){
      security_message(phpgenPort);
    }
  }
}
