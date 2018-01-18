###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_teamviewer_insecure_lib_load_vuln.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# TeamViewer File Opening Insecure Library Loading Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:teamviewer:teamviewer";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
             code and conduct DLL hijacking attacks via a Trojan horse dwmapi.dll that is
             located in the same folder as a .tvs or .tvc file.
             Impact Level: Application.";

tag_affected = "TeamViewer version 5.0.8703 and prior";

tag_insight = "The flaw is due to the application insecurely loading certain
              librairies from the current working directory.";

tag_solution = "Update to version 5.0.9104 or later,
                             For updates refer to http://www.teamviewer.com/index.aspx";

tag_summary = "This host is installed with TeamViewer and is prone to insecure
                                     library loading vulnerability.";

if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.801436");
    script_version("$Revision: 8447 $");
    script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
    script_tag(name:"creation_date", value:"2010-09-08 14:19:28 +0200 (Wed, 08 Sep 2010)");
    script_cve_id("CVE-2010-3128");
    script_tag(name:"cvss_base", value:"9.3");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
    script_name("TeamViewer File Opening Insecure Library Loading Vulnerability");
    script_xref(name : "URL", value : "http://secunia.com/advisories/41112");
    script_xref(name : "URL", value : "http://www.exploit-db.com/exploits/14734/");
    script_xref(name : "URL", value : "http://www.vupen.com/english/advisories/2010/2174");

    script_tag(name:"qod_type", value:"registry");
    script_category(ACT_GATHER_INFO);
    script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
    script_family("General");
    script_dependencies("gb_teamviewer_win_detect.nasl");
    script_mandatory_keys("teamviewer/Ver");
    script_tag(name : "insight", value : tag_insight);
    script_tag(name : "solution", value : tag_solution);
    script_tag(name : "summary", value : tag_summary);
    script_tag(name : "impact", value : tag_impact);
    script_tag(name : "affected", value : tag_affected);
    script_tag(name:"solution_type", value:"VendorFix");

    exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!Ver = get_app_version(cpe:CPE)) {
    exit(0);
}

if(version_is_less(version:Ver, test_version:"5.0.9104"))
{
    report = report_fixed_ver(installed_version:Ver, fixed_version:"5.0.9104");
    security_message(data:report);
    exit(0);
}

