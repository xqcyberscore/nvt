###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cyrus_imap_server_bof_vuln.nasl 4919 2017-01-02 15:22:45Z cfi $
#
# Cyrus IMAP Server SIEVE Script Handling Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_solution = "Apply patches or upgrade to the latest version,
  http://bugzilla.andrew.cmu.edu/cgi-bin/cvsweb.cgi/src/sieve/script.c.diff?r1=1.67&r2=1.68
  http://bugzilla.andrew.cmu.edu/cgi-bin/cvsweb.cgi/src/sieve/script.c.diff?r1=1.62&r2=1.62.2.1&only_with_tag=cyrus-imapd-2_2-tail

  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attackers to crash an affected server
  or execute arbitrary code via a malicious SIEVE Script.
  Impact Level: Application";
tag_affected = "Cyrus IMAP Server versions 2.3.14 and prior.";
tag_insight = "The flaw is caused is due to error in the handling of 'SIEVE' Script, that
  fails to perform adequate boundary checks on user-supplied data.";
tag_summary = "This host is running Cyrus IMAP Server and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(902223);
  script_version("$Revision: 4919 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-02 16:22:45 +0100 (Mon, 02 Jan 2017) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2009-2632");
  script_bugtraq_id(36296, 36377);
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Cyrus IMAP Server SIEVE Script Handling Buffer Overflow Vulnerability");

  script_xref(name : "URL" , value : "http://www.debian.org/security/2009/dsa-1881");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2559");
  script_xref(name : "URL" , value : "https://www.redhat.com/archives/fedora-package-announce/2009-September/msg00491.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_cyrus_imap_server_detect.nasl");
  script_mandatory_keys("Cyrus/IMAP4/Server/Ver");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);

  exit(0);
}


include("version_func.inc");

imapVer = get_kb_item("Cyrus/IMAP4/Server/Ver");
if(!imapVer){
  exit(0);
}

## Check for Cyrus IMAP Server <= 2.3.14
if(version_is_less_equal(version:imapVer, test_version:"2.3.14")){
  security_message(0);
}
