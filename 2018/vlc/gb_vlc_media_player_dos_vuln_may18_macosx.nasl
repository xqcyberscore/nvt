###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vlc_media_player_dos_vuln_may18_macosx.nasl 10387 2018-07-04 05:21:03Z cfischer $
#
# VLC Media Player Denial-of-Service Vulnerability May18 (Mac OS X)
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
  script_oid("1.3.6.1.4.1.25623.1.0.813502");
  script_version("$Revision: 10387 $");
  script_cve_id("CVE-2018-11516");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 07:21:03 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-05-29 12:32:46 +0530 (Tue, 29 May 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("VLC Media Player Denial-of-Service Vulnerability May18 (Mac OS X)");

  script_tag(name: "summary" , value:"The host is installed with VLC media player
  and is prone to denial-of-service vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaws exist due to an error in
  the 'vlc_demux_chained_Delete' function in input/demux_chained.c file while
  reading a crafted .swf file.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to cause a denial of service (heap corruption and application crash)
  or possibly have unspecified other impact.

  Impact Level: Application");

  script_tag(name: "affected" , value:"VideoLAN VLC media player version 3.0.1
  on Mac OS X");

  script_tag(name: "solution" , value:"Update to version 3.0.2 or above.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://code610.blogspot.in/2018/05/make-free-vlc.html");
  script_xref(name : "URL" , value : "https://www.videolan.org");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_vlc_media_player_detect_macosx.nasl");
  script_mandatory_keys("VLC/Media/Player/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vlcVer = infos['version'];
vlcpath = infos['location'];

if(vlcVer == "3.0.1")
{
  report = report_fixed_ver(installed_version:vlcVer, fixed_version:"3.0.2", install_path: vlcpath);
  security_message(data:report);
  exit(0);
}

exit(0);
