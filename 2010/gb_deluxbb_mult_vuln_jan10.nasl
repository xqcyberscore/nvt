###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_deluxbb_mult_vuln_jan10.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# DeluxeBB Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an
  affected site.
  Impact Level: Application.";
tag_affected = "DeluxeBB version 1.3 and prior.";
tag_insight = "The flaws are due to:
  - Improper sanitization of user supplied input in the 'page' parameter in
    'misc.php'.
  - Improperly controlled computation in 'tools.php' that leads to a denial
    of service (CPU or memory consumption).
  - Web root with insufficient access control, which allows to obtain user and
    configuration information, log data, and gain administrative access via a
    direct request to scripts in 'templates/including', 'logs/cp.php', 'images/',
    'templates/deluxe/admincp/', 'templates/corporate/admincp/', 'logs/including'
    'templates/blue/admincp/','wysiwyg/', 'docs/', 'classes/', 'lang/;' and
    'settings/'.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";
tag_summary = "The host is running DeluxeBB and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800436");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4465", "CVE-2009-4466", "CVE-2009-4467", "CVE-2009-4468");
  script_bugtraq_id(37448);
  script_name("DeluxeBB Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54980");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54977");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54975");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10598");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_dependencies("deluxeBB_detect.nasl");
  script_family("Web application abuses");
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

dbbPort = get_http_port(default:80);
if(!dbbPort){
  exit(0);
}

dbbVer = get_kb_item("www/" + dbbPort + "/deluxeBB");
if(!dbbVer){
  exit(0);
}

dbbVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dbbVer);
if(!safe_checks() && dbbVer[2] != NULL)
{
    request = http_get(item:dbbVer[2] + "/templates/corporate/admincp/",
                       port:dbbPort);
    response = http_send_recv(port:dbbPort, data:request);
    if("Index of" >< response && "/templates/corporate/admincp" >< response)
    {
      security_message(dbbPort);
      exit(0);
    }
}

if(dbbVer[1] != NULL)
{
  if(version_is_less_equal(version:dbbVer[1], test_version:"1.3")){
    security_message(dbbPort);
  }
}
