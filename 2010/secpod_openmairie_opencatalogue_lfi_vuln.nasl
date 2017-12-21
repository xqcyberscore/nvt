##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openmairie_opencatalogue_lfi_vuln.nasl 8187 2017-12-20 07:30:09Z teissa $
#
# openMairie openCatalogue 'dsn[phptype]' Local File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to include
or disclose the contents of local files with the privileges of the web server.

Impact Level: Application.";

tag_affected = "OpenMairie openCatalogue version 1.024 and prior";

tag_insight = "Input passed to the parameter 'dsn[phptype]' in 'scr/soustab.php'
is not properly verified before being used to include files.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running openMairie openCatalogue and is prone to
local file inclusion vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902054");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1999");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("openMairie openCatalogue 'dsn[phptype]' Local File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39688");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1051");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1005-exploits/opencatalogue-lfi.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_openmairie_prdts_detect.nasl");
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

openPort = get_http_port(default:80);
if(!get_port_state(openPort)){
  exit(0);
}

openVer = get_kb_item("www/"+ openPort + "/OpenMairie/Open_Catalogue");
if(!openVer){
  exit(0);
}

openVer = eregmatch(pattern:"^(.+) under (/.*)$", string:openVer);

if(openVer[2] != NULL)
{
  ## Check the exploit
  sndReq = http_get(item:string(openVer[2], "/scr/soustab.php?dsn[phptype]=" +
                    "../../../../../../../../OpenVas-rfi.txt"),port:openPort);
  rcvRes = http_send_recv(port:openPort, data:sndReq);

  ## Check attack response
  if("/OpenVas-rfi.txt/" >< rcvRes && "failed to open stream" >< rcvRes){
    security_message(openPort);
  }
}
