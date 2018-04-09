###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for lftp CESA-2009:1278 centos5 i386
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "LFTP is a sophisticated file transfer program for the FTP and HTTP
  protocols. Like bash, it has job control and uses the readline library for
  input. It has bookmarks, built-in mirroring, and can transfer several files
  in parallel. It is designed with reliability in mind.

  It was discovered that lftp did not properly escape shell metacharacters
  when generating shell scripts using the &quot;mirror --script&quot; command. A
  mirroring script generated to download files from a malicious FTP server
  could allow an attacker controlling the FTP server to run an arbitrary
  command as the user running lftp. (CVE-2007-2348)
  
  This update also fixes the following bugs:
  
  * when using the &quot;mirror&quot; or &quot;get&quot; commands with the &quot;-c&quot; option, lftp did
  not check for some specific conditions that could result in the program
  becoming unresponsive, hanging and the command not completing. For example,
  when waiting for a directory listing, if lftp received a &quot;226&quot; message,
  denoting an empty directory, it previously ignored the message and kept
  waiting. With this update, these conditions are properly checked for and
  lftp no longer hangs when &quot;-c&quot; is used with &quot;mirror&quot; or &quot;get&quot;. (BZ#422881)
  
  * when using the &quot;put&quot;, &quot;mput&quot; or &quot;reput&quot; commands over a Secure FTP (SFTP)
  connection, specifying the &quot;-c&quot; option sometimes resulted in corrupted
  files of incorrect size. With this update, using these commands over SFTP
  with the &quot;-c&quot; option works as expected, and transferred files are no
  longer corrupted in the transfer process. (BZ#434294)
  
  * previously, LFTP linked to the OpenSSL library. OpenSSL's license is,
  however, incompatible with LFTP's GNU GPL license and LFTP does not include
  an exception allowing OpenSSL linking. With this update, LFTP links to the
  GnuTLS (GNU Transport Layer Security) library, which is released under the
  GNU LGPL license. Like OpenSSL, GnuTLS implements the SSL and TLS
  protocols, so functionality has not changed. (BZ#458777)
  
  * running &quot;help mirror&quot; from within lftp only presented a sub-set of the
  available options compared to the full list presented in the man page. With
  this update, running &quot;help mirror&quot; in lftp presents the same list of mirror
  options as is available in the Commands section of the lftp man page.
  (BZ#461922)
  
  * LFTP imports gnu-lib from upstream. Subsequent to gnu-lib switching from
  GNU GPLv2 to GNU GPLv3, the LFTP license was internally inconsistent, with
  LFTP licensed a ... 

  Description truncated, for more information please check the Reference URL";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "lftp on CentOS 5";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2009-September/016139.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880878");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name: "CESA", value: "2009:1278");
  script_cve_id("CVE-2007-2348");
  script_name("CentOS Update for lftp CESA-2009:1278 centos5 i386");

  script_tag(name:"summary", value:"Check for the Version of lftp");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"lftp", rpm:"lftp~3.7.11~4.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
