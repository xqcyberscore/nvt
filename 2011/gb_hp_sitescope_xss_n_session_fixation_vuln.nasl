###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_sitescope_xss_n_session_fixation_vuln.nasl 5390 2017-02-21 18:39:27Z mime $
#
# HP SiteScope Cross-Site Scripting and Session Fixation Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "Apply the patch from below link,
  For updates refer to http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02940969

  *****
  NOTE : Ignore this warning if above mentioned patch is applied already.
  *****";

tag_impact = "Successful exploitation could allow execution of scripts or actions written
  by an attacker. In addition, an attacker may conduct session fixation attacks
  to hijack the target user's session.
  Impact Level: Application";
tag_affected = "HP SiteScope version 9.x, 10.x, and 11.x";
tag_insight = "Multiple flaws are due to,
  - Certain unspecified input is not properly sanitised before being returned
    to the user. This can be exploited to execute arbitrary HTML and script
    code in a user's browser session in context of an affected site.
  - An error in the handling of sessions can be exploited to hijack another
    user's session by tricking the user into logging in after following a
    specially crafted link.";
tag_summary = "This host is running HP SiteScope and is prone to cross-site
  scripting and session fixation vulnerabilities.";

if(description)
{
  script_id(801976);
  script_version("$Revision: 5390 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-2400", "CVE-2011-2401");
  script_bugtraq_id(48916, 48913);
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:P/A:P");
  script_name("HP SiteScope Cross-Site Scripting and Session Fixation Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/45440");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025856");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68867");
  script_xref(name : "URL" , value : "http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02940969");

  script_tag(name:"qod_type", value:"remote_banner");
  script_summary("Determine if installed SiteScope version is vulnerable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("SiteScope/banner");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get the server banner
banner = get_http_banner(port:port);
if(!banner){
  exit(0);
}

## Confirm the server
if("Server: SiteScope/" >!< banner){
  exit(0);
}

## Match the version
version = eregmatch(pattern:"Server: SiteScope/([^ ]+)", string:banner);
if(isnull(version[1])){
  exit(0);
}

## Check for the version 9.x, 10.x, and 11.x
if(version_is_less_equal(version:version[1], test_version:"9.54") ||
   version_in_range(version:version[1], test_version:"11.0", test_version2:"11.10") ||
   version_in_range(version:version[1], test_version:"10.0", test_version2:"10.14")) {
  security_message(port:port);
}
