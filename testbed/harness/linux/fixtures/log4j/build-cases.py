"""log4j-check 하네스의 시료 — Maven Central 의 공식 jar 와, 그것을 꾸리거나 다시 묶은 것.

경우 하나가 <out>/<경우>/ 폴더 하나다(하네스가 그 폴더만 컨테이너의 /scan 에 붙인다). 기대값은 <out>/expect.tsv:
  묶음 <TAB> 경우 <TAB> 기대 종료 코드(0 · 2 · 6) <TAB> 메모
실검체는 없다 — 공식 배포 jar 를 그대로 두거나 zip 으로 다시 묶을 뿐이고, 아무것도 실행하지 않는다.
  usage: python3 -I -X utf8 build-cases.py <official.txt> <공식 jar 폴더> <out 폴더>
"""
import io
import os
import shutil
import sys
import zipfile

table, jars, out = sys.argv[1], sys.argv[2], sys.argv[3]
shutil.rmtree(out, ignore_errors=True)
os.makedirs(out)
rows = []
CLASS = bytes.fromhex('cafebabe')  # 클래스 파일의 머리 네 바이트뿐 — 내용은 없다
STORED = zipfile.ZIP_STORED  # Spring Boot 는 안쪽 jar 를 압축하지 않고 담는다


def jar(name):
    with open(os.path.join(jars, name), 'rb') as f:
        return f.read()


def put(group, case, files, want, note):
    """files: (이름, 바이트) 의 목록 — 경우 폴더 하나에 둔다."""
    d = os.path.join(out, case)
    os.makedirs(d, exist_ok=True)
    for name, data in files:
        with open(os.path.join(d, name), 'wb') as f:
            f.write(data)
    rows.append((group, case, str(want), note))


def zbytes(entries):
    """entries: (이름, 바이트) 또는 (이름, 바이트, 압축 방법) — 기본은 deflate(실제 배포 꼴)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for e in entries:
            z.writestr(zipfile.ZipInfo(e[0]), e[1], compress_type=e[2] if len(e) > 2 else zipfile.ZIP_DEFLATED)
    return buf.getvalue()


def members(data, drop=()):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        return [(i.filename, z.read(i.filename)) for i in z.infolist()
                if not i.is_dir() and i.filename not in drop]


# ── B. 공식 jar 를 제 이름 그대로 — official.txt 의 줄마다 한 경우
with open(table, encoding='utf-8') as f:
    for line in f:
        if not line.strip() or line.startswith('#'):
            continue
        _, artifact, version, want, note = (line.split(None, 4) + [''])[:5]
        name = f'{artifact}-{version}.jar'
        put('B', f'b-{artifact}-{version}', [(name, jar(name))], want, note.strip())

core = jar('log4j-core-2.14.1.jar')
fixed = jar('log4j-core-2.17.1.jar')
v1 = jar('log4j-1.2.17.jar')
WEB = ('WEB-INF/web.xml', b'<web-app/>')
APP = ('META-INF/application.xml', b'<application/>')
BOOT = [('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\nMain-Class: org.springframework.boot.loader.JarLauncher\n'),
        ('BOOT-INF/classes/com/example/App.class', CLASS)]

# ── C. 꾸린 앱 — 실제 배포처럼 deflate 로 묶는다
put('C', 'c01-renamed', [('app-logging.jar', core)], 2, '이름을 바꾼 공식 2.14.1 — 해시로 안다')
put('C', 'c02-war', [('app.war', zbytes([WEB, ('WEB-INF/lib/log4j-core-2.14.1.jar', core)]))], 2, 'war 의 WEB-INF/lib')
put('C', 'c03-war-fixed', [('app.war', zbytes([WEB, ('WEB-INF/lib/log4j-core-2.17.1.jar', fixed)]))], 0,
    '고친 판을 담은 war')
put('C', 'c04-ear', [('app.ear', zbytes([APP, ('lib/log4j-core-2.14.1.jar', core)]))], 2, 'ear 의 lib')
war = zbytes([WEB, ('WEB-INF/lib/log4j-core-2.14.1.jar', core)])
put('C', 'c05-ear-war-jar', [('app.ear', zbytes([APP, ('web/app.war', war)]))], 2, 'ear 안 war 안 jar — 두 겹')
put('C', 'c06-boot', [('app.jar', zbytes(BOOT + [('BOOT-INF/lib/log4j-core-2.14.1.jar', core, STORED)]))], 2,
    'Spring Boot')
put('C', 'c07-boot-renamed', [('app.jar', zbytes(BOOT + [('BOOT-INF/lib/logging-lib.jar', core, STORED)]))], 2,
    'Spring Boot · 이름을 바꾼 안쪽 공식 2.14.1')
put('C', 'c08-boot-renamed-fixed', [('app.jar', zbytes(BOOT + [('BOOT-INF/lib/logging-lib.jar', fixed, STORED)]))],
    0, 'Spring Boot · 이름을 바꾼 안쪽 고친 판')
put('C', 'c09-shaded', [('uber.jar', zbytes(members(core) + [('com/example/Main.class', CLASS)]))], 2,
    'shade — log4j-core 의 클래스와 좌표를 앱 jar 에 옮겨 담았다')
jndi = 'org/apache/logging/log4j/core/lookup/JndiLookup.class'
put('C', 'c10-jndi-removed', [('log4j-core-2.14.1.jar', zbytes(members(core, drop=(jndi,))))], 2,
    'JndiLookup.class 를 뺀 jar — 45105 · 44832 가 남는다')
v1_pom = [(n, d) for n, d in members(v1) if n.startswith('META-INF/maven/')]
put('C', 'c11-masked', [('app.jar', zbytes(v1_pom + [('lib/log4j-core-2.14.1.jar', core)]))], 2,
    '최상위의 log4j 1.2.17 좌표 + 안쪽 2.14.1')
guava = zbytes([('com/google/X.class', CLASS)])
put('C', 'c12-clean-war', [('app.war', zbytes([WEB, ('WEB-INF/lib/guava-31.1-jre.jar', guava)]))], 0,
    '로깅 라이브러리가 없다')
put('C', 'c13-war-unversioned', [('app.war', zbytes([WEB, ('WEB-INF/lib/log4j-core.jar', core)]))], 2,
    '압축한 war · 판이 없는 안쪽 이름')
put('C', 'c14-rebuilt', [('log4j-core.jar', zbytes(members(core)))], 2,
    '다시 묶은 2.14.1(공식 바이트가 아니다) · 판이 없는 이름 — 배포판 패키지 꼴')
put('C', 'c15-war-other-name', [('app.war', zbytes([WEB, ('WEB-INF/lib/logging-lib.jar', core)]))], 2,
    '압축한 war · 엉뚱한 이름의 안쪽 2.14.1')
put('C', 'c16-v1-unreleased', [('log4j-1.3.0.jar', zbytes([('org/apache/log4j/Logger.class', CLASS)]))], 2,
    '1.x 는 전부 취약 — 1.3 은 정식 판이 나오지 않은 알파 줄')

# ── D. 크기 — 채움은 정해진 바이트(PK 가 나오지 않는다)
filler = bytes(range(256)) * (12 * 4096)
big = zbytes([BOOT[0], ('BOOT-INF/lib/filler.jar', filler, STORED),
              ('BOOT-INF/lib/log4j-core-2.14.1.jar', core, STORED)])
put('D', 'd01-big-boot', [('app.jar', big)], 2, '12 MiB Spring Boot')
many = [(f'lib-{i:02d}.jar', fixed) for i in range(80)]
put('D', 'd02-many-jars', many + [('z-logging.jar', core)], 2, 'jar 81개 · 이름을 바꾼 공식 2.14.1 하나')
put('D', 'd03-many-clean', many, 0, '고친 판 80개 — 깨끗한 서버는 깨끗하다')

# ── E. 모르는 것
put('E', 'e01-truncated', [('app.jar', fixed[:len(fixed) // 2])], 6, '잘린 jar — zip 머리는 있고 끝 표지가 없다')
pom = b'groupId=org.apache.logging.log4j\nartifactId=log4j-core\n'
coords = 'META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties'
put('E', 'e02-no-version', [('app.jar', zbytes([(coords, pom), ('com/example/Main.class', CLASS)]))], 6,
    'log4j-core 의 좌표에 판이 없다')
put('E', 'e03-not-zip', [('data.jar', bytes(range(256)) * 64)], 0, 'zip 이 아닌 .jar — 아카이브가 아니다')

with open(os.path.join(out, 'expect.tsv'), 'w', encoding='utf-8', newline='\n') as f:
    for r in rows:
        f.write('\t'.join(r) + '\n')
print(f'경우 {len(rows)} -> {out}')
