###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_backup_exec_prdts_cmd_exec_vuln_win.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Symantec Backup Exec Products Arbitrary Command Execution vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to cause privilege
  escalation by executing post authentication NDMP commands.
  Impact Level: Application.";
tag_affected = "Symantec Backup Exec for Windows Servers versions 11.0, 12.0, 12.5
  Symantec Backup Exec 2010 versions 13.0, 13.0 R2";

tag_insight = "The flaw is due to weakness in communication protocol implementation
  and lack of validation of identity information exchanged between media server
  and remote agent.";
tag_solution = "Upgrade to the Symantec Backup Exec 2010 R3
  For updates refer to http://www.symantec.com/business/products/family.jsp?familyid=backupexec";
tag_summary = "This host is installed with Symantec Backup Exec Products and is
  prone to arbitrary command execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801798");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-17 11:16:31 +0200 (Fri, 17 Jun 2011)");
  script_cve_id("CVE-2011-0546");
  script_bugtraq_id(47824);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");
  script_name("Symantec Backup Exec Products Arbitrary Command Execution vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44698");
  script_xref(name : "URL" , value : "http://www.symantec.com/business/security_response/securityupdates/detail.jsp?");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_symantec_backup_exec_detect.nasl");
  script_mandatory_keys("Symantec/BackupExec/Win/Installed");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Check for Symantec Backup Exec for Windows Servers Version
servInfos = get_app_version_and_location( cpe:"cpe:/a:symantec:veritas_backup_exec_for_windows_servers" );
servVers  = servInfos['version'];
servPath  = servInfos['location'];

if( servVers ) {
  if( version_in_range( version:servVers, test_version:"11.0", test_version2:"12.5.2213" ) ) {
    report = report_fixed_ver( installed_version:servVers, fixed_version:"See references", install_path:servPath );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

## Check for Symantec Backup Exec for 2010 Version
infos = get_app_version_and_location( cpe:"cpe:/a:symantec:backup_exec", exit_no_version:TRUE );
vers  = infos['version'];
path  = infos['location'];

if( version_in_range( version:vers, test_version:"13.0", test_version2:"13.0.4164" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"13.0 R3", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );