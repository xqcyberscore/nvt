###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_justsystems_ichitaro_prdts_dos_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# JustSystems Ichitaro Products Denial of Service Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_solution = "Apply the patch for JustSystems Ichitaro from below link
  http://www.justsystems.com/jp/info/js11001.html

  Upgrade to JustSystems Ichitaro viewer version 20.0.4.0 or later
  For updates refer to http://www.justsystems.com/jp/info/js11001.html

  *****
  NOTE: Ignore this warning, if patch is applied already.
  *****";

tag_impact = "Successful exploitation will let attackers to execute arbitrary code on the
  vulnerable system or cause the application to crash.
  Impact Level: System/Application";
tag_affected = "JustSystems Ichitaro version 2005 through 2011
  JustSystems Ichitaro viewer version prior to 20.0.4.0";
tag_insight = "The flaw is due to the error while parsing certain documents.";
tag_summary = "This host is installed with JustSystems Ichitaro product(s) and is
  prone to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902396");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_bugtraq_id(48283);
  script_cve_id("CVE-2011-1331");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("JustSystems Ichitaro Products Denial of Service Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/44956");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN87239473/index.html");
  script_xref(name : "URL" , value : "http://www.justsystems.com/jp/info/js11001.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000043.html");
  script_xref(name : "URL" , value : "http://www.symantec.com/connect/blogs/targeted-attacks-2011-using-ichitaro-zero-day-vulnerability");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_justsystems_ichitaro_prdts_detect.nasl");
  script_mandatory_keys("Ichitaro/Ichitaro_or_Viewer/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

# check for Ichitaro 2005 through 2011
ichitaroVer = get_kb_item("Ichitaro/Ver");
if(ichitaroVer)
{
  if(version_in_range(version:ichitaroVer, test_version:"2005", test_version2:"2011"))
  {
    security_message(0);
    exit(0);
  }
}

# Check for Ichitaro viewer version prior to 20.0.4.0
viewerVer = get_kb_item("Ichitaro/Viewer/Ver");
if(viewerVer)
{
  if(version_is_less(version:viewerVer, test_version:"20.0.4.0")){
    security_message(0);
  }
}
