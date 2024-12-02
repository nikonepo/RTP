import os
import random
import string
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pyshark
import pytest

# pylint: disable=missing-function-docstring, too-many-arguments

used_ports = {}
LANG = os.getenv("PROTOCOL_LANG", "python")
CAPTURE_FILE_NAME = "crypted.pcap"


@pytest.fixture(scope="module", autouse=True)
def compile_protocol():
    if LANG == "python":
        pass
    try:
        if LANG == "cpp":
            build_dir = "./cpp/build"
            if not os.path.exists(build_dir):
                os.makedirs(build_dir)
            cmake_command = ["cmake", ".."]
            subprocess.run(cmake_command, cwd=build_dir, check=True)
            build_command = ["cmake", "--build", ".", "--target", "protocol"]
            subprocess.run(build_command, cwd=build_dir, check=True, stderr=subprocess.PIPE)
        if LANG == "golang":
            if not os.path.exists("./golang/build"):
                os.makedirs("./golang/build")
            compile_command = ["go", "build", "-o", "build/protocol", "."]
            subprocess.run(compile_command, cwd="./golang", check=True, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        if e.stderr is not None:
            print(e.stderr.decode("utf-8"), flush=True)
        raise RuntimeError("Ошибка при сборке") from e

    except FileNotFoundError as e:
        raise RuntimeError("Ошибка: компилятор или интерпретатор не найден.") from e


def generate_port():
    while True:
        port = random.randrange(25000, 30000)
        if port not in used_ports:
            break
    used_ports[port] = True
    return port


def run_protocol(
    client: bool, local_addr, local_port, msg, remote_addr, remote_port, iterations=1, timeout=None
):
    common_params = [
        "client" if client else "server",
        local_addr,
        str(local_port),
        str(len(msg)),
        remote_addr,
        str(remote_port),
        str(iterations),
    ]
    if LANG == "python":
        command = ["python", "-m", "protocol"] + common_params
        cwd = "./python"
    elif LANG == "cpp":
        command = ["./build/protocol"] + common_params
        cwd = "./cpp"
    elif LANG == "golang":
        command = ["./build/protocol"] + common_params
        cwd = "./golang"
    else:
        raise RuntimeError("lang invalid")

    try:
        # Запускаем процесс с Popen
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,  # Для передачи данных в стандартный ввод
            stdout=subprocess.PIPE,  # Захватываем стандартный вывод
            stderr=subprocess.PIPE,  # Захватываем ошибки
            cwd=cwd,  # Директория для выполнения команды
            preexec_fn=os.setsid,
        )

        # Передаем данные в stdin и ждем завершения с таймаутом
        stdout, stderr = process.communicate(input=msg, timeout=timeout)

        # Проверяем успешное завершение
        if process.returncode != 0:
            raise subprocess.CalledProcessError(
                process.returncode, command, output=stdout, stderr=stderr
            )

        return client, 0, stdout
    except FileNotFoundError as exc:
        raise RuntimeError("Программа не найдена") from exc

    except subprocess.TimeoutExpired as e:
        # Прерываем процесс и его дочерние процессы при превышении таймаута
        print(f"Процесс превысил время ожидания, прерывание... {process.pid}")
        os.killpg(os.getpgid(process.pid), subprocess.signal.SIGINT)
        process.wait(timeout=timeout)
        raise TimeoutError("Процесс был завершен по таймауту") from e

    except subprocess.CalledProcessError as e:
        # Обработка ошибок выполнения команды
        print(f"Ошибка при выполнении команды: {e}")
        print(f"Ошибка выполнения программы: {e.stderr.decode('utf-8')}")
        raise RuntimeError("Ошибка выполнения программы") from e


def run_test(iterations, msg_size, timeout):
    a_addr = ("127.0.0.1", generate_port())
    b_addr = ("127.0.0.1", generate_port())
    random_input = os.urandom(msg_size)

    with ThreadPoolExecutor(max_workers=2) as executor:
        # Сначала запускаем сервер
        server_future = executor.submit(
            run_protocol,
            *(False, a_addr[0], a_addr[1], random_input, b_addr[0], b_addr[1], iterations, timeout),
        )
        # Добавляем задержку перед запуском клиента, чтобы сервер успел стартовать
        time.sleep(0.1)
        # Запускаем клиента
        client_future = executor.submit(
            run_protocol,
            *(True, b_addr[0], b_addr[1], random_input, a_addr[0], a_addr[1], iterations, timeout),
        )

        # Ожидаем завершения выполнения обоих процессов
        results = []
        for future in as_completed([server_future, client_future]):
            results.append(future.result())
    server_result = results[0]
    client_result = results[1]

    for out in client_result[2].split(b"\n")[-1]:
        assert out == random_input
    for out in server_result[2].split(b"\n")[-1]:
        assert int(out) == msg_size


def execute_netem_command(command):
    try:
        subprocess.run([*command.split(" ")], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        try:
            subprocess.run(["sudo", *command.split(" ")], check=True, capture_output=True)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError("Не возможно установить netem") from exc


@pytest.fixture(scope="function", params=[(0, 0, 0)])
def setup_netem(request):
    netem_set_cmd = (
        f"tc qdisc replace dev lo root netem loss {request.param[0] * 100}% "
        f"duplicate {request.param[1] * 100}%"
    )
    netem_del_cmd = "tc qdisc del dev lo root"
    if request.param[2] > 0:
        netem_set_cmd += f" reorder {100 - request.param[2]}% delay 10ms"
    print(f"Applied netem: {netem_set_cmd}", flush=True)
    execute_netem_command(netem_set_cmd)
    yield
    execute_netem_command(netem_del_cmd)


@pytest.mark.parametrize("iterations", [10, 50, 100])
@pytest.mark.parametrize("timeout", [30])
def test_basic(iterations, timeout):
    run_test(iterations=iterations, msg_size=11, timeout=timeout)


@pytest.mark.parametrize("iterations", [100, 500, 1000])
@pytest.mark.parametrize("timeout", [30])
@pytest.mark.parametrize("setup_netem", [(0.02, 0, 0)], indirect=True, ids=["small"])
def test_small_loss(iterations, setup_netem, timeout):
    run_test(iterations=iterations, msg_size=11, timeout=timeout)


@pytest.mark.parametrize("iterations", [100, 500, 1000])
@pytest.mark.parametrize("timeout", [30])
@pytest.mark.parametrize("setup_netem", [(0.1, 0, 0)], indirect=True, ids=["high"])
def test_high_loss(iterations, setup_netem, timeout):
    run_test(iterations=iterations, msg_size=11, timeout=timeout)


@pytest.mark.parametrize("iterations", [100, 500, 1000])
@pytest.mark.parametrize("timeout", [30])
@pytest.mark.parametrize("setup_netem", [(0, 0.02, 0)], indirect=True, ids=["small"])
def test_small_duplicate(iterations, setup_netem, timeout):
    run_test(iterations=iterations, msg_size=11, timeout=timeout)


@pytest.mark.parametrize("iterations", [100, 500, 1000])
@pytest.mark.parametrize("timeout", [30])
@pytest.mark.parametrize("setup_netem", [(0, 0.1, 0)], indirect=True, ids=["high"])
def test_high_duplicate(iterations, setup_netem, timeout):
    run_test(iterations=iterations, msg_size=11, timeout=timeout)


@pytest.mark.parametrize("iterations", [2])
@pytest.mark.parametrize("msg_size", [65536, 200000, 5_000_000])
@pytest.mark.parametrize("timeout", [180])
@pytest.mark.parametrize("setup_netem", [(0.02, 0.02, 0.01)], indirect=True, ids=["high"])
def test_large_message(iterations, setup_netem, timeout, msg_size):
    run_test(iterations=iterations, msg_size=msg_size, timeout=timeout)


@pytest.mark.parametrize("iterations", [50_000])
@pytest.mark.parametrize("timeout", [60])
@pytest.mark.parametrize("setup_netem", [(0.02, 0.02, 0.01)], indirect=True, ids=["high"])
def test_perfomance(iterations, timeout, setup_netem):
    run_test(iterations=iterations, msg_size=10, timeout=timeout)


def run_pyshark(capture, timeout):
    capture.sniff(timeout=timeout)
    return True


def generate_random_string(length) -> bytes:
    if length < 1:
        raise ValueError("Length must be a positive integer.")
    characters = string.ascii_letters
    return str("".join(random.choice(characters) for _ in range(length))).encode()


def run_test_tls(iterations, msg_size, timeout):
    a_addr = ("127.0.0.1", generate_port())
    b_addr = ("127.0.0.1", generate_port())
    random_ascii_string = generate_random_string(msg_size)
    capture = pyshark.LiveCapture(
        "lo", bpf_filter=f"udp port {a_addr[1]}", output_file=CAPTURE_FILE_NAME
    )
    capture_thread = threading.Thread(target=run_pyshark, args=(capture, timeout))
    capture_thread.start()
    with ThreadPoolExecutor(max_workers=2) as executor:
        server_future = executor.submit(
            run_protocol,
            *(
                False,
                a_addr[0],
                a_addr[1],
                random_ascii_string,
                b_addr[0],
                b_addr[1],
                iterations,
                timeout,
            ),
        )
        # Добавляем задержку перед запуском клиента, чтобы сервер успел стартовать
        time.sleep(0.1)
        # Запускаем клиента
        client_future = executor.submit(
            run_protocol,
            *(
                True,
                b_addr[0],
                b_addr[1],
                random_ascii_string,
                a_addr[0],
                a_addr[1],
                iterations,
                timeout,
            ),
        )

        # Ожидаем завершения выполнения обоих процессов
        results = []
        for future in as_completed([server_future, client_future]):
            results.append(future.result())
    capture_thread.join()
    server_result = results[0]
    client_result = results[1]

    for out in client_result[2].split(b"\n")[-1]:
        assert out == random_ascii_string
    for out in server_result[2].split(b"\n")[-1]:
        assert int(out) == msg_size
    return random_ascii_string, a_addr, b_addr


@pytest.mark.parametrize("timeout", [10])
@pytest.mark.parametrize("iterations", [100])
@pytest.mark.parametrize("setup_netem", [(0.02, 0.02, 0.01)], indirect=True, ids=["high"])
def test_tls_basic(timeout, setup_netem, iterations):
    pattern, a_addr, b_addr = run_test_tls(iterations, 100, timeout)
    capture = pyshark.FileCapture(CAPTURE_FILE_NAME, display_filter=f"udp.port == {a_addr[1]}")
    for packet in capture:
        udp_payload = bytes.fromhex(packet.udp.payload.replace(':', ''))
        assert pattern not in udp_payload
