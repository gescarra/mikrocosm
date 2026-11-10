# =====================================================================
#  OPTIONAL. The pipeline doesn't use this.
#  Kept around like a spare tyre: unused, mildly reassuring.
#
#  Every job installs its toolchain with pip at run time from a stock
#  python:3.12-slim-bookworm image, because building a custom one needs two
#  things a small self-hosted GitLab often lacks: a container registry (without
#  it $CI_REGISTRY is unset and `docker login` silently retries against Docker
#  Hub) and a PRIVILEGED runner for docker-in-docker. See the note at the top
#  of .gitlab-ci.yml.
#
#  Pre-bake this instead if you want the seconds back, or if you want the
#  dependency versions pinned rather than resolved per job. This image sits
#  in the path of a `reset-configuration` on a live border router, and
#  "whatever pip resolved this morning" is a fair thing to object to.
#
#      docker build -t <your-registry>/netdevops:main -f ci/Dockerfile .
#      docker push  <your-registry>/netdevops:main
#
#  Then set IMAGE in .gitlab-ci.yml and the `image:` in ci/child-jobs.yml to
#  that tag and drop the pip/apt lines from both before_script blocks. Nothing
#  else in the pipeline cares where the image came from.
# =====================================================================
FROM python:3.12-slim-bookworm

# ---- network tooling the tests actually need -------------------------
#  openssh-client   every router interaction is ssh/scp from the control node
#  iputils-ping     the e2e ICMP checks (v4 and v6 both come from this)
#  traceroute       path inspection when e2e fails and you need to see where
#  ca-certificates  the address reflectors and the bulk transfer are HTTPS
#  curl             debugging by hand inside a failed job
#  dnsutils         resolution checks, and looking up what the fleet publishes
#  iproute2         reading the runner's own addresses (the e2e "where am I")
#  git              the deploy job re-renders from the checked-out commit
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-client \
        iputils-ping \
        traceroute \
        ca-certificates \
        curl \
        dnsutils \
        iproute2 \
        git \
    && rm -rf /var/lib/apt/lists/*

# ---- python: the generator's deps, plus the test and deploy tooling ---
# ansible-core, not the full `ansible` bundle: the only collections used here
# are ansible.builtin and ansible.utils, and pulling ~100 unused collections
# into an image that talks to production routers is surface for nothing.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir \
        "ansible-core==2.17.6" \
        "pytest==8.3.4" \
        "pytest-cov==6.0.0" \
    && ansible-galaxy collection install ansible.utils:==5.1.2 \
    && rm /tmp/requirements.txt

# ansible.utils provides the `in_network` test, which is what the end-to-end
# assertion is written in: "is the address the internet sees inside our /24".

WORKDIR /build

# A sanity check at BUILD time rather than at rollout time. If the image can't
# import the generator's dependencies or run ansible, that should fail here,
# not on a runner three jobs into a rollout.
RUN python -c "import jinja2, yaml, cryptography" \
    && ansible --version \
    && pytest --version
