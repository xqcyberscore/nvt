###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_apr_n_apr_util_iof_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apache APR and APR-util Multiple Integer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_solution = "Upgrade to Apache APR version 1.3.8 or APR-util version 1.3.9,
  http://apr.apache.org/download.cgi
  or
  Apply the patches for Apache APR-Utils 0.9.x or Apache APR version 0.9.x
  http://www.apache.org/dist/apr/patches/apr-0.9-CVE-2009-2412.patch
  http://www.apache.org/dist/apr/patches/apr-util-0.9-CVE-2009-2412.patch

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in
  the context of an affected application, and can cause Denial of Service.
  Impact Level: Application";
tag_affected = "Apache APR version 0.9.x and 1.3.x before 1.3.8
  Apache APR-Utils version 0.9.x and 1.3.x before 1.3.9";
tag_insight = "- Error exists when vectors trigger crafted calls to the allocator_alloc
    or apr_palloc function in memory/unix/apr_pools.c in APR.
  - Error in apr_rmm_malloc, apr_rmm_calloc or apr_rmm_realloc function in
    misc/apr_rmm.c caused while aligning relocatable memory blocks in
    APR-util.";
tag_summary = "The host is installed with Apache APR and APR-Util and is prone to
  multiple Integer Overflow vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800679");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-17 14:35:19 +0200 (Mon, 17 Aug 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2412");
  script_bugtraq_id(35949);
  script_name("Apache APR and APR-util Multiple Integer Overflow Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/36138");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36140");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_apache_apr-utils_detect.nasl", "gb_apache_apr_detect.nasl");
  script_mandatory_keys("Apache/APR_or_Utils/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

apruVer = get_kb_item("Apache/APR-Utils/Ver");
aprVer = get_kb_item("Apache/APR/Ver");

# Apache APR-util
if(apruVer != NULL)
{
  # Check for Apache APR-util version 0.9 <= 0.9.17 or 1.3.x < 1.3.9
  if(version_in_range(version:apruVer, test_version:"0.9.0", test_version2:"0.9.17")||
     version_in_range(version:apruVer, test_version:"1.3.0", test_version2:"1.3.8")){
    security_message(0);
  }
}

# Apache APR
if(aprVer != NULL)
{
  # Check for Apache APR version 0.9 <= 0.9.18 or 1.3.x < 1.3.8
  if(version_in_range(version:aprVer, test_version:"0.9.0", test_version2:"0.9.18")||
     version_in_range(version:aprVer, test_version:"1.3.0", test_version2:"1.3.7")){
    security_message(0);
  }
}
