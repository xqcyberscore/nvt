###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_thunderbird_mult_vuln_july08_lin.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Mozilla Thunderbird Multiple Vulnerability July-08 (Linux)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could result in remote arbitrary code execution,
  spoofing attacks, sensitive information disclosure, and can crash the browser.
  Impact Level: System";
tag_summary = "The host is installed with Mozilla Thunderbird, that is prone
  to multiple vulnerabilities.";

tag_affected = "Thunderbird version prior to 2.0.0.16 on Linux.";
tag_insight = "The issues are due to,
  - multiple errors in the layout and JavaScript engines that can corrupt
    memory.
  - error while handling unprivileged XUL documents that can be exploited
    to load chrome scripts from a fastload file via <script> elements.
  - error in mozIJSSubScriptLoader.LoadScript function that can bypass
    XPCNativeWrappers.
  - error in block re-flow process, which can potentially lead to crash.
  - errors in the implementation of the Javascript same origin policy
  - error in processing of Alt Names provided by peer.
  - error in processing of windows URL shortcuts.";
tag_solution = "Upgrade to Thunderbird version 2.0.0.16
  http://www.mozilla.com/en-US/thunderbird/all-older.html";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800021");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-07 14:21:23 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2802", "CVE-2008-2803",
                "CVE-2008-2807", "CVE-2008-2809", "CVE-2008-2811");
  script_bugtraq_id(30038);
  script_xref(name:"CB-A", value:"08-0109");
  script_name("Mozilla Thunderbird Multiple Vulnerability July-08 (Linux)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_lin.nasl");
  script_mandatory_keys("Thunderbird/Linux/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-21.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-24.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-25.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-29.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-31.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-33.html");
  exit(0);
}


# Grep for thunderbird version < 2.0.0.16
if(egrep(pattern:"^([01]\..*|2\.0(\.0\.(0?[0-9]|1[0-5]))?)$",
         string:get_kb_item("Thunderbird/Linux/Ver"))){
  security_message(0);
}
