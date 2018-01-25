###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lussumo_vanilla_mult_remote_file_incl_vuln.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# Lussumo Vanilla 'definitions.php' Remote File Include Vulnerabilities
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

tag_impact = "Successful exploitation will let attackers to execute arbitrary
code in a user's browser session in the context of an affected site.

Impact Level: Application";

tag_affected = "Lussumo Vanilla version 1.1.10 and prior.";

tag_insight = "The flaw is due to an error in the 'include' and
'Configuration[LANGUAGE]' parameters, which allows remote attackers to send
a specially-crafted URL request to the 'definitions.php' script.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Lussumo Vanilla and is prone remote file include
  vulnerabilities";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800757");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_cve_id("CVE-2010-1337");
  script_bugtraq_id(38889);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Lussumo Vanilla 'definitions.php' Remote File Include Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57147");
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.com/1003-exploits/vanilla-rfi.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_lussumo_vanilla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

vanillaPort = get_http_port(default:80);
if(!vanillaPort){
  exit(0);
}

vanillaVer = get_kb_item("www/" + vanillaPort + "/Lussumo/Vanilla");
if(!vanillaVer){
  exit(0);
}

vanillaVer = eregmatch(pattern:"^(.+) under (/.*)$", string:vanillaVer);
if(vanillaVer[1] != NULL)
{
  if(version_is_less_equal(version:vanillaVer[1], test_version:"1.1.10")){
    security_message(vanillaPort);
  }
}

