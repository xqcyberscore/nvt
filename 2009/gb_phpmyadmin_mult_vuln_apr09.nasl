###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_mult_vuln_apr09.nasl 4869 2016-12-29 11:01:45Z teissa $
#
# phpMyAdmin Multiple Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_solution = "Upgrade to version 2.11.9.5 or 3.1.3.1
  http://www.phpmyadmin.net/home_page/downloads.php

  Workaround:
  Update the existing PHP files from the below SVN Revisions.
  http://phpmyadmin.svn.sourceforge.net/viewvc/phpmyadmin?view=rev&revision=12301
  http://phpmyadmin.svn.sourceforge.net/viewvc/phpmyadmin?view=rev&revision=12302
  http://phpmyadmin.svn.sourceforge.net/viewvc/phpmyadmin?view=rev&revision=12303

  *****
  Note: Igone the warning, if already replaced according to the fixed svn
        revision numbers.
  *****";

tag_impact = "Successful exploitation will let the attacker cause XSS, Directory Traversal
  attacks or can injection malicious PHP Codes to gain sensitive information
  about the remote host.";
tag_affected = "phpMyAdmin version 2.11.x to 2.11.9.4 and 3.0.x to 3.1.3";
tag_insight = "Multiple flaws are due to,
  - BLOB streaming feature in 'bs_disp_as_mime_type.php' causes CRLF Injection
    which lets the attacker inject arbitrary data in the HTTP headers through
    the 'c_type' and 'file_type' parameters.
  - XSS Vulnerability in 'display_export.lib.php' as its not sanitizing the
    'pma_db_filename_template' parameter.
  - Static code injection vulnerability in 'setup.php' which can be used to
    inject PHP Codes.
  - Filename 'bs_disp_as_mime_type.php' which is not sanitizing user supplied
    inputs in the filename variable which causes directory traversal attacks.";
tag_summary = "This host is running phpMyAdmin and is prone to multiple
  vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800381";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 4869 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 12:01:45 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-04-20 14:33:23 +0200 (Mon, 20 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1148", "CVE-2009-1149", "CVE-2009-1150", "CVE-2009-1151");
  script_bugtraq_id(34251, 34253, 34236);
  script_name("phpMyAdmin Multiple Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/34430");
  script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2009-1.php");
  script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2009-2.php");
  script_xref(name : "URL" , value : "http://www.phpmyadmin.net/home_page/security/PMASA-2009-3.php");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("phpMyAdmin/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

pmaPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!pmaPort){
  pmaPort = 80;
}

pmaVer = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:pmaPort);
if(!pmaVer){
  exit(0);
}

pmaVer = eregmatch(pattern:"^(.+) under (/.*)$", string:pmaVer);
if(pmaVer[1])
{
  if(version_in_range(version:pmaVer[1], test_version:"2.11", test_version2:"2.11.9.4")||
     version_in_range(version:pmaVer[1], test_version:"3.0", test_version2:"3.1.3")){
    security_message(pmaPort);
  }
}
