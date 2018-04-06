###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_informix_dynamic_server_code_exec_vuln_lin.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM Informix Dynamic Server Oninit Remote Code Execution Vulnerability (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM-level privileges.
  Impact Level: System/Application";
tag_affected = "IBM Informix Dynamic Server (IDS) version 11.50";
tag_insight = "The flaw is due to a boundary error in the oninit process bound to TCP
  port 9088 when processing the arguments to the USELASTCOMMITTED option in a
  SQL query.";
tag_solution = "Upgrade to IBM Informix IDS version 11.50.xC8 or later,
  For updates refer to http://www-01.ibm.com/software/data/informix/";
tag_summary = "This host is installed with IBM Informix Dynamic Server and is
  prone to remote code execution vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902548");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-02 09:08:31 +0200 (Tue, 02 Aug 2011)");
  script_cve_id("CVE-2011-1033");
  script_bugtraq_id(46230);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("IBM Informix Dynamic Server Oninit Remote Code Execution Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43212");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65209");
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-11-050/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_ibm_informix_dynamic_server_detect_lin.nasl");
  script_require_keys("IBM/Informix/Dynamic/Server/Lin/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

## Get version from KB
version = get_kb_item("IBM/Informix/Dynamic/Server/Lin/Ver");
if(version)
{
  ## Check for IBM Informix Dynamic Server (IDS) version 11.50
  if(version_is_equal(version:version, test_version:"11.50")){
    security_message(0);
  }
}
