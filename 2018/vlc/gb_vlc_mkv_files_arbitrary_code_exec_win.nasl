###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_mkv_files_arbitrary_code_exec_win.nasl 10538 2018-07-18 10:58:40Z santu $
#
# VLC Media Player MKV Files Arbitrary Code Execution Vulnerability (Windows)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813579");
  script_version("$Revision: 10538 $");
  script_cve_id("CVE-2018-11529");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-07-18 12:58:40 +0200 (Wed, 18 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-17 11:32:20 +0530 (Tue, 17 Jul 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("VLC Media Player MKV Files Arbitrary Code Execution Vulnerability (Windows)");

  script_tag(name: "summary" , value:"The host is installed with VLC media player
  and is prone to arbitrary code execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exist due to an improper sanitization
  used by VLC media player against MKV files.");

  script_tag(name: "impact" , value:"Successful exploitation will allow attackers
  to execute arbitrary code in the context of the logged-in user and failed
  exploit attempts will likely result in denial of service conditions.

  Impact Level: Application");

  script_tag(name: "affected" , value:"VideoLAN VLC media player versions through
  2.2.8 on Windows");

  script_tag(name: "solution" , value:"Update to version 3.0.3 or above.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2018/Jul/28");
  script_xref(name : "URL" , value : "https://www.videolan.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vlcVer = infos['version'];
vlcpath = infos['location'];

if(version_is_less_equal(version:vlcVer, test_version:"2.2.8"))
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"3.0.3", install_path: vlcpath);
  security_message(data:report);
  exit(0);
}
