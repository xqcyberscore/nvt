###############################################################################
# OpenVAS Vulnerability Test
#
# ManageEngine ServiceDesk Plus Multiple XSS Vulnerabilities
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801962");
  script_version("2019-06-24T11:38:56+0000");
  script_tag(name:"last_modification", value:"2019-06-24 11:38:56 +0000 (Mon, 24 Jun 2019)");
  script_tag(name:"creation_date", value:"2011-08-04 10:01:53 +0200 (Thu, 04 Aug 2011)");
  script_bugtraq_id(48928);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("ManageEngine ServiceDesk Plus Multiple XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://sebug.net/exploit/20793/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68717");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17586/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manageengine_servicedesk_plus_consolidation.nasl");
  script_mandatory_keys("manageengine/servicedesk_plus/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable
  site. This may allow an attacker to steal cookie-based authentications and
  launch further attacks.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus 8.0 Build 8013 and prior.");

  script_tag(name:"insight", value:"Multiple flaws are due to an error in,

  - 'SetUpWizard.do' when handling configuration wizard (add new technician)
  action via 'Name' parameter.

  - 'SiteDef.do' when handling add a new site action via 'Site name' parameter.

  - 'GroupResourcesDef.do' when handling add a create group action via
  'Group Name' parameter.

  - 'LicenseAgreement.do' when handling add a new license agreement action via
  'Agreement Number' parameter.

  - 'ManualNodeAddition.do' when handling server configuration (computer)
  action via 'Name' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running ManageEngine ServiceDesk Plus and is prone
  to multiple cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = "cpe:/a:zohocorp:manageengine_servicedesk_plus";

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:version, test_version:"8.0b8013" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"None", install_path:path );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );
