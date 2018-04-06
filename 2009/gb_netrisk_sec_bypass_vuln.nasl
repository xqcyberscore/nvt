###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netrisk_sec_bypass_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# NetRisk Security Bypass Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to bypass
security restrictions and change the password of arbitrary users via direct
request.

Impact Level: Application";

tag_affected = "NetRisk version 1.9.7 and prior.";

tag_insight = "The vulnerability is caused because the application does not
properly restrict access to 'admin/change_submit.php'.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with NetRisk and is prone to security
bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800940");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7155");
  script_bugtraq_id(27150);
  script_name("NetRisk Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/39465");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2008-7155");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/27150.pl");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_netrisk_detect.nasl");
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

netriskPort = get_http_port(default:80);

if(!netriskPort)
{
  exit(0);
}

netriskVer = get_kb_item("www/" + netriskPort + "/NetRisk");
netriskVer = eregmatch(pattern:"^(.+) under (/.*)$", string:netriskVer);

if(netriskVer[1] != NULL)
{
  if(version_is_less_equal(version:netriskVer[1], test_version:"1.9.7")){
    security_message(netriskPort);
  }
}
