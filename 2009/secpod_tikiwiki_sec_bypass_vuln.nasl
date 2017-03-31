###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tikiwiki_sec_bypass_vuln.nasl 5144 2017-01-31 09:55:46Z cfi $
#
# Tiki Wiki CMS Groupware Authentication Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901002");
  script_version("$Revision: 5144 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-31 10:55:46 +0100 (Tue, 31 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-1574");
  script_bugtraq_id(14170);
  script_name("Tiki Wiki CMS Groupware Authentication Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod ");
  script_family("Web application abuses");
  script_dependencies("secpod_tikiwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TikiWiki/installed");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/40347");
  script_xref(name:"URL", value:"http://sourceforge.net/tracker/index.php?func=detail&aid=748739&group_id=64258&atid=506846");

  tag_impact = "Successful exploitation could allows to bypass the authentication process to
  gain unauthorized access to the system with the privileges of the victim.

  Impact Level: Application";

  tag_affected = "Tiki Wiki CMS Groupware Version 1.6.1 on all running platform.";

  tag_insight = "The flaw is due to improper validation of user login credentials. By
  entering a valid username, an arbitrary or null password, and clicking on the
  'remember me' button.";

  tag_solution = "Upgrade to version 1.7.1.1 or latest
  http://info.tikiwiki.org/Get+Tiki";

  tag_summary = "The host is installed with Tiki Wiki CMS Groupware and is prone to Authentication
  Bypass vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"1.6.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.7.1.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );