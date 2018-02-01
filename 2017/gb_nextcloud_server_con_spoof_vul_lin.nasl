###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nextcloud_server_con_spoof_vul_lin.nasl 8595 2018-01-31 08:04:59Z cfischer $
#
# Nextcloud Server CVE-2017-0888 Content Spoofing Vulnerability (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:nextcloud:nextcloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107145");
  script_version("$Revision: 8595 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-31 09:04:59 +0100 (Wed, 31 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-04-10 09:39:06 +0200 (Mon, 10 Apr 2017)");
  script_cve_id("CVE-2017-0883", "CVE-2017-0884", "CVE-2017-0885", "CVE-2017-0886",
                "CVE-2017-0887", "CVE-2017-0888");
  script_bugtraq_id(97491);
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name(" Nextcloud Server CVE-2017-0888 Content Spoofing Vulnerability (Linux)");
  script_tag(name: "summary", value: "Nextcloud Server is prone to Multiple vulnerabilities.");

  script_tag(name: "vuldetect", value: "Get the installed version with the help of
  detect NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "Multiple flaw exist due to

  - The top navigation bar displayed in the files list contained partially
    user-controllable input leading to a potential misrepresentation of information.
  
  - Due to an error in the application logic an authenticated adversary may trigger
    an endless recursion in the application.

  - Due to not properly sanitizing values provided by the `OC-Total-Length` HTTP
    header an authenticated adversary may be able to exceed their configured user
    quota.

  - Due to an error in the application logic an adversary with access to a
    write-only share may enumerate the names of existing files and subfolders by
    comparing the exception messages.
 
  - A permission related issue within the OCS sharing API allowed an authenticated
    adversary to reshare shared files with an increasing permission set.
 
  - Due to a logical error in the file caching layer an authenticated adversary is
    able to create empty folders inside a shared folder.");

  script_tag(name: "impact" , value: "Successful exploitation will allow an attacker
  to edit files in a share, lead to a potential misrepresentation of information,
  and can cause denail of service condition.

  Impact Level: Application");

  script_tag(name: "affected", value: "Versions prior to Nextcloud Server 9.0.55
  and 10.0.2 are vulnerable");
  script_tag(name: "solution", value: "Updates are available. Please see the
  references or vendor advisory for more information.");
  script_xref(name: "URL" , value: "http://www.securityfocus.com/bid/97491");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("Web application abuses");

  script_dependencies("gb_nextcloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe:CPE, port:Port)){
  exit(0);
}

if (Ver =~"9\.0\.")
{
    if(version_is_less(version: Ver, test_version:"9.0.55"))
    {
        Vuln = TRUE;
        fix = "9.0.55";
    }
}
else if ( Ver =~ "10\.0\." )
{
    if(version_is_less(version: Ver, test_version:"10.0.2"))
    {
        Vuln = TRUE;
        fix = "10.0.2";
    }
}

if (Vuln)
{
    report =  report_fixed_ver(installed_version:Ver, fixed_version:fix);
    security_message(data:report);
    exit(0);
}
