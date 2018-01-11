###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_storage_mirroring_unspecified_vuln.nasl 8356 2018-01-10 08:00:39Z teissa $
#
# HP StorageWorks Storage Mirroring Unspecified Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:adobe:photoshop_cc2017";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary code
  via unknown vectors.
  Impact Level: Application/System";
tag_affected = "HP StorageWorks Storage Mirroring version 5 before 5.2.1.870.0";
tag_insight = "The flaw is caused by unspecified errors.";
tag_solution = "Upgrade to HP StorageWorks Storage Mirroring version 5.2.1.870.0 or later,
  For updates refer to http://h18006.www1.hp.com/products/storage/software/sm/index.html?psn=storage";
tag_summary = "This host is installed with HP StorageWorks Storage Mirroring and is
  prone to unspecified vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801357");
  script_version("$Revision: 8356 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 09:00:39 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-15 06:05:27 +0200 (Tue, 15 Jun 2010)");
  script_cve_id("CVE-2010-1962"); 
  script_bugtraq_id(40539); 
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("HP StorageWorks Storage Mirroring Unspecified Vulnerability");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_storage_mirroring_detect.nasl");
  script_mandatory_keys("HP/SWSM/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://marc.info/?l=bugtraq&m=127557820805729&w=2");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1319");
  script_xref(name : "URL" , value : "http://securityvulns.com/news/HP/StorageWorks/StorageMirrori.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

## Grep for HP StorageWorks Storage Mirroring version 5 before 5.2.1.870.0
if( version_in_range( version:vers, test_version:"5.0", test_version2:"5.2.1.869" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.1.870.0", install_path:path );
  security_message( port:0, data:report );
}

exit( 99 );