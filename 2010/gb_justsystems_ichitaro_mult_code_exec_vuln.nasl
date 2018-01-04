##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_justsystems_ichitaro_mult_code_exec_vuln.nasl 8269 2018-01-02 07:28:22Z teissa $
#
# JustSystems Ichitaro Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
################################i###############################################

tag_solution = "Apply the patch, available from below link
  http://www.justsystems.com/jp/info/js10003.html

  *****
  NOTE: Ignore this warning, if above mentioned workaround is manually applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to execute arbitrary code
  within the context of the vulnerable application.
  Impact Level: Application.";
tag_affected = "JustSystems Ichitaro 2004 through 2010";
tag_insight = "The flaws are caused by an unspecified error when processing a malformed
  document, which could be exploited to execute arbitrary code.";
tag_summary = "This host is installed JustSystems Ichitaro and is prone to
  multiple code execution vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801642");
  script_version("$Revision: 8269 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-02 08:28:22 +0100 (Tue, 02 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-30 12:42:12 +0100 (Tue, 30 Nov 2010)");
  script_cve_id("CVE-2010-3915", "CVE-2010-3916");
  script_bugtraq_id(44637);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("JustSystems Ichitaro Multiple Remote Code Execution Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/42099");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62997");
  script_xref(name : "URL" , value : "http://www.justsystems.com/jp/info/js10003.html");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2885");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_justsystems_ichitaro_prdts_detect.nasl");
  script_require_keys("Ichitaro/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

## Get the version from KB
ichitaroVer = get_kb_item("Ichitaro/Ver");

if(ichitaroVer)
{
  # check for Ichitaro 2004 through 2010
  if(version_in_range(version:ichitaroVer, test_version:"2004", test_version2:"2010")){
    security_message(0);
  }
}
