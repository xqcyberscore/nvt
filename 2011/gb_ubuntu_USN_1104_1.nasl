###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ubuntu_USN_1104_1.nasl 7964 2017-12-01 07:32:11Z santu $
#
# Ubuntu Update for ffmpeg vulnerabilities USN-1104-1
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
tag_insight = "Cesar Bernardini and Felipe Andres Manzano discovered that FFmpeg
  incorrectly handled certain malformed flic files. If a user were tricked
  into opening a crafted flic file, an attacker could cause a denial of
  service via application crash, or possibly execute arbitrary code with the
  privileges of the user invoking the program. This issue only affected
  Ubuntu 8.04 LTS, 9.10 and 10.04 LTS. (CVE-2010-3429)

  Dan Rosenberg discovered that FFmpeg incorrectly handled certain malformed
  wmv files. If a user were tricked into opening a crafted wmv file, an
  attacker could cause a denial of service via application crash, or possibly
  execute arbitrary code with the privileges of the user invoking the
  program. This issue only affected Ubuntu 8.04 LTS, 9.10 and 10.04 LTS.
  (CVE-2010-3908)
  
  It was discovered that FFmpeg incorrectly handled certain malformed ogg
  files. If a user were tricked into opening a crafted ogg file, an attacker
  could cause a denial of service via application crash, or possibly execute
  arbitrary code with the privileges of the user invoking the program.
  (CVE-2010-4704)
  
  It was discovered that FFmpeg incorrectly handled certain malformed WebM
  files. If a user were tricked into opening a crafted WebM file, an attacker
  could cause a denial of service via application crash, or possibly execute
  arbitrary code with the privileges of the user invoking the program.
  (CVE-2011-0480)
  
  Dan Rosenberg discovered that FFmpeg incorrectly handled certain malformed
  RealMedia files. If a user were tricked into opening a crafted RealMedia
  file, an attacker could cause a denial of service via application crash, or
  possibly execute arbitrary code with the privileges of the user invoking
  the program. This issue only affected Ubuntu 8.04 LTS, 9.10 and 10.04 LTS.
  (CVE-2011-0722)
  
  Dan Rosenberg discovered that FFmpeg incorrectly handled certain malformed
  VC1 files. If a user were tricked into opening a crafted VC1 file, an
  attacker could cause a denial of service via application crash, or possibly
  execute arbitrary code with the privileges of the user invoking the
  program. (CVE-2011-0723)";

tag_summary = "Ubuntu Update for Linux kernel vulnerabilities USN-1104-1";
tag_affected = "ffmpeg vulnerabilities on Ubuntu 8.04 LTS ,
  Ubuntu 9.10 ,
  Ubuntu 10.04 LTS ,
  Ubuntu 10.10";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name: "URL" , value: "http://www.ubuntu.com/usn/usn-1104-1/");
  script_id(840629);
  script_version("$Revision: 7964 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 08:32:11 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-04-06 16:20:31 +0200 (Wed, 06 Apr 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "USN", value: "1104-1");
  script_cve_id("CVE-2010-3429", "CVE-2010-3908", "CVE-2010-4704", "CVE-2011-0480", "CVE-2011-0722", "CVE-2011-0723");
  script_name("Ubuntu Update for ffmpeg vulnerabilities USN-1104-1");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-deb.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "UBUNTU9.10")
{

  if ((res = isdpkgvuln(pkg:"ffmpeg-dbg", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ffmpeg", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavcodec52", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavdevice-dev", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavdevice52", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavfilter-dev", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavfilter0", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat52", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavutil49", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpostproc-dev", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpostproc51", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libswscale0", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"0.5+svn20090706-2ubuntu2.3", rls:"UBUNTU9.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.10")
{

  if ((res = isdpkgvuln(pkg:"ffmpeg-dbg", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ffmpeg", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavcodec52", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavdevice-dev", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavdevice52", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavfilter-dev", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavfilter1", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat52", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavutil50", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpostproc-dev", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpostproc51", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libswscale0", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"0.6-2ubuntu6.1", rls:"UBUNTU10.10")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU10.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"ffmpeg-dbg", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ffmpeg", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavcodec52", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavdevice-dev", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavdevice52", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavfilter-dev", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavfilter0", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat52", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavutil49", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpostproc-dev", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpostproc51", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libswscale0", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"0.5.1-1ubuntu1.1", rls:"UBUNTU10.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}


if(release == "UBUNTU8.04 LTS")
{

  if ((res = isdpkgvuln(pkg:"libavcodec-dev", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavcodec1d", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat-dev", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavformat1d", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavutil-dev", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libavutil1d", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpostproc-dev", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libpostproc1d", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libswscale-dev", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"libswscale1d", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isdpkgvuln(pkg:"ffmpeg", ver:"0.cvs20070307-5ubuntu7.6", rls:"UBUNTU8.04 LTS")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
