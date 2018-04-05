###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-103.nasl 9323 2018-04-05 08:44:52Z cfischer $
#
# Microsoft VS Team Foundation Server SignalR XSS Vulnerability (2905244)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:microsoft:visual_studio_team_foundation_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901227");
  script_version("$Revision: 9323 $");
  script_cve_id("CVE-2013-5042");
  script_bugtraq_id(64093);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-05 10:44:52 +0200 (Thu, 05 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-12-11 10:49:08 +0530 (Wed, 11 Dec 2013)");
  script_name("Microsoft VS Team Foundation Server SignalR XSS Vulnerability (2905244)");

  tag_summary = "This host is missing an important security update according to Microsoft
  Bulletin MS13-103.";

  tag_vuldetect = "Get the vulnerable file version and check appropriate patch is applied
  or not.";

  tag_insight = "Flaw is due ASP.NET SignalR improperly encodes user input before returning
  it to the user.";

  tag_impact = "Successful exploitation will allow attackers to execute arbitrary script
  code in a user's browser within the trust relationship between their
  browser and the server.

  Impact Level: Application";

  tag_affected = "Microsoft Visual Studio Team Foundation Server 2013";

  tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,

  https://technet.microsoft.com/en-us/security/bulletin/ms13-103";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2903566");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-103");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_vs_team_foundation_server_detect.nasl");
  script_mandatory_keys("MS/VS/Team/Foundation/Server/Ver");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vs_tfs_ver = infos['version'];
if(vs_tfs_ver !~ "^2013"){
  exit(0);
}
vs_tfs_path = infos['location'];
if(vs_tfs_path && "Could not find the install location" >!< vs_tfs_path)
{
  signalr_file = "\Application Tier\Web Services\bin\Microsoft.AspNet.SignalR.Core.dll";

  ## Get Version from Microsoft.AspNet.SignalR.Core.dll
  vs_tfs_file_ver = fetch_file_version(sysPath: vs_tfs_path, file_name:signalr_file);

  if(vs_tfs_file_ver)
  {
    ## Check for version less than 1.1.21022.0
    if(version_is_less(version:vs_tfs_file_ver, test_version:"1.1.21022.0"))
    {
      security_message(0);
      exit(0);
    }
  }
}

exit(99);