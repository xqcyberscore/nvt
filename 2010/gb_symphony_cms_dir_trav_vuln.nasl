###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symphony_cms_dir_trav_vuln.nasl 5373 2017-02-20 16:27:48Z teissa $
#
# Symphony CMS Directory traversal vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to view files and
execute local scripts in the context of the web server process, which may aid
in further attacks.

Impact Level: Application";

tag_affected = "Symphony CMS Version 2.0.7";

tag_insight = "The flaw is caused by improper validation of user-supplied input
via the 'mode' parameter in 'index.php' that allows the attackers to view files
and execute local scripts in the context of the web server.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running Symphony CMS and is prone to directory
traversal vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801220";
CPE = "cpe:/a:symphony-cms:symphony_cms";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5373 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 17:27:48 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-2143");
  script_bugtraq_id(40441);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Symphony CMS Directory traversal vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12809/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1005-exploits/symphony-lfi.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_symphony_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("symphony/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  exit(0);
}

## Get version from KB
symphonyVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port);
if(symphonyVer)
{
  ## Check for Symphony CMS version 2.0.7
  if(version_is_equal(version:symphonyVer, test_version:"2.0.7")) {
    security_message(port);
  }
}
