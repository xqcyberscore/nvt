###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mem_corrpt_n_int_underflow_vuln_macosx.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Mozilla Firefox Memory Corruption and Integer Underflow Vulnerabilities (MAC OS X)
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

tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code
  with the privileges of the user running the affected application. Failed
  attempts may trigger a denial-of-service condition.
  Impact Level: Application";
tag_affected = "Mozilla Firefox 3.6.x before 3.6.23";
tag_insight = "The flaws are due to
  - An integer underflow error exists within the Regular Expression engine
    when evaluating certain regular expressions.
  - An unspecified error can be exploited to corrupt memory.";
tag_solution = "Upgrade to Firefox version 3.6.23 or later
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox and is prone to memory
  corruption and integer underflow vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802181");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_cve_id("CVE-2011-2996", "CVE-2011-2998");
  script_bugtraq_id(49845, 49809);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Mozilla Firefox Memory Corruption and Integer Underflow Vulnerabilities (MAC OS X)");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-36.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_require_keys("Mozilla/Firefox/MacOSX/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Firefox Check
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");
if(ffVer)
{
  ## Grep for Firefox versions before 4.0
  if(version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.22")){
    security_message(0);
  }
}
