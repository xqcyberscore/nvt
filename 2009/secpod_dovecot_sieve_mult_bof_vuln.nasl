###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dovecot_sieve_mult_bof_vuln.nasl 5055 2017-01-20 14:08:39Z teissa $
#
# Dovecot Sieve Plugin Multiple Buffer Overflow Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
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

tag_solution = "Apply the patch  or upgrade to Dovecot version 1.1.4 or 1.1.7
  http://www.dovecot.org/download.html
  http://hg.dovecot.org/dovecot-sieve-1.1/rev/049f22520628
  http://hg.dovecot.org/dovecot-sieve-1.1/rev/4577c4e1130d

  *****
  NOTE: Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful attack could allow malicious people to crash an affected
  application or execute arbitrary code.
  Impact Level: Application";
tag_affected = "Dovecot versions 1.0 before 1.0.4 and 1.1 before 1.1.7";
tag_insight = "Multiple buffer overflow errors in the CMU libsieve when processing
  malicious SIEVE scripts.";
tag_summary = "This host has Dovecot Sieve Plugin installed and is prone to
  multiple Buffer Overflow Vulnerabilities";

if(description)
{
  script_id(901026);
  script_version("$Revision: 5055 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-20 15:08:39 +0100 (Fri, 20 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-3235");
  script_bugtraq_id(36377);
  script_name("Dovecot Sieve Plugin Multiple Buffer Overflow Vulnerabilities");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53248");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2641");
  script_xref(name : "URL" , value : "http://www.dovecot.org/list/dovecot-news/2009-September/000135.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_dovecot_detect.nasl");
  script_require_keys("Dovecot/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("version_func.inc");

dovecotVer = get_kb_item("Dovecot/Ver");
if(dovecotVer != NULL)
{
  if(version_in_range(version:dovecotVer, test_version:"1.0", test_version2:"1.0.3") ||
    version_in_range(version:dovecotVer, test_version:"1.1", test_version2:"1.1.6"))
  {
    security_message(0);
    exit(0);
  }
}
