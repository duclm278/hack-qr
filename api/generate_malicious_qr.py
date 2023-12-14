import time

import common
import cv2
import hamming
import numpy as np
import qr
from PIL import Image
from qrcodegen import *


def unwrap(desc):
    (f, args, kwargs) = desc
    return f(*args, **kwargs)


def task(args):
    # Start 3. from here
    original_message, malicious_message, ecc, version, mask = args
    q0 = qr.generate_qr_code(original_message, ecc, version, mask)
    q0 = qr.qr_matrix(q0)

    # 3. Generate corresponding QR codes Qi for the messages Mi, i =
    # 1,...,n. The new QR codes should use the same version and mask as the
    # original QR code, so no changes in these regions of the QR code need
    # to be done.
    qr_code = qr.generate_qr_code(malicious_message, ecc, version, mask)
    qr_code_matrix = qr.qr_matrix(qr_code)

    # 4. Construct the symmetric difference Di of the generated QR code to
    # the original, for each Qi in qr_codes.
    # dx = symmetric_diff(q0, qr_code_matrix)

    # 5. Calculate the ratios ri of modules in the symmetric differences
    # that indicate a change from white to black.
    # ri = calculate_ratio(q0, qr_code_matrix, dx)

    # 6. Order the QR codes by ratio ri, descending. Codes where the number
    # of codewords (not modules) that need to get changed from black to
    # white is higher than the error-correcting capacity of the code can be
    # omitted.

    # 7. Start with the first QR code Q1 (now sorted) and color white
    # modules of Q0 that are black in Q1 black.
    # Check after every module, whether the meaning of the QR code can be
    # decoded and results in a different message than the original. Repeat
    # this until a valid coloring is found (for the first b elements the
    # check can be omitted, where b denotes the number of errors the
    # BCH-encoding is capable of correcting plus one. If the resulting code
    # Qi' can get decoded to message Mi, a solution was found.
    # In step seven, the following optimization can be used: Instead of coloring
    # module by module, we simply change all modules that can be changed by only
    # using black color at once and thus generate Qx by applying the fast and
    # simple element-wise OR-function: Qx = Q0 OR Rx, (OR = element-wise OR).
    # Q0 = target code,
    # Qx = generated code,
    # Rx = Qx AND Dx (AND = element-wise AND)
    # Dx = Q0 XOR Qx,
    # Qx = code in qr_codes
    return is_code_valid((q0, original_message, qr_code_matrix))


def generate_malicious_qr(message, ecc, version, mask, image_name):
    common.init_pool()

    print(">>> QR CODE")
    print("Message: ", message)
    print("ECC: ", ecc)
    print("Version: ", version)
    print("Mask: ", mask)

    q0 = qr.generate_qr_code(message, ecc, version, mask)
    q0 = qr.qr_matrix(q0)

    # Try for each hamming distance
    start_p = None
    for i in range(1, len(message)):
        print(">>> HAMMING DISTANCE: ", i)
        # 2. Generate several messages Mi, i = 1,...,n, that contain URLs to
        # possible phishing sites (the new messages are generated in a way to
        # make them look similar to the original one, e.g. by systematically
        # changing characters in the original URL).
        start_m = time.time()
        print("Generating messages...")
        malicious_messages = hamming.generate_messages(
            message, i
        )  # ['http://yghqo.at']
        print("Number of messages: ", len(malicious_messages))
        print("Finished in: ", time.time() - start_m)

        start_p = time.time()
        print("Generating solutions...")
        args = [
            (task, ((message, mm, ecc, version, mask),), {})
            for mm in malicious_messages
        ]
        check_codes = common.POOL.imap_unordered(unwrap, args)
        for check_code in check_codes:
            if check_code:
                print("Found solution, terminating...")
                common.POOL.terminate()
                common.POOL.join()
                print("Finished in: ", time.time() - start_p)
                return save_solution(q0, message, check_code, image_name)
        print("Finished in: ", time.time() - start_p)
    return ""


# def generate_malicious_qr(message, ecc, version, mask, image_name):
#     print(">>> QR CODE")
#     print("Message: ", message)
#     print("ECC: ", ecc)
#     print("Version: ", version)
#     print("Mask: ", mask)

#     q0 = qr.generate_qr_code(message, ecc, version, mask)
#     q0 = qr.qr_matrix(q0)

#     # Try for each hamming distance
#     for i in range(1, len(message)):
#         print(">>> HAMMING DISTANCE: ", i)
#         # 2. Generate several messages Mi, i = 1,...,n, that contain URLs to
#         # possible phishing sites (the new messages are generated in a way to
#         # make them look similar to the original one, e.g. by systematically
#         # changing characters in the original URL).
#         start_m = time.time()
#         print("Generating messages...")
#         messages = hamming.generate_messages(message, i)  # ['http://yghqo.at']
#         print("Number of messages: ", len(messages))
#         print("Finished in: ", time.time() - start_m)

#         # 3. Generate corresponding QR codes Qi for the messages Mi, i =
#         # 1,...,n. The new QR codes should use the same version and mask as the
#         # original QR code, so no changes in these regions of the QR code need
#         # to be done.
#         start_q = time.time()
#         print("Generating QR codes...")
#         # qr_codes = [
#         #     qr.generate_qr_code(message, ecc, version, mask) for message in messages
#         # ]
#         args = [
#             (qr.generate_qr_code, (message, ecc, version, mask), {})
#             for message in messages
#         ]
#         qr_codes = common.POOL.map(unwrap, args)

#         # qr_code_matrices = [qr.qr_matrix(q) for q in qr_codes]
#         args = [(qr.qr_matrix, (q,), {}) for q in qr_codes]
#         qr_code_matrices = common.POOL.map(unwrap, args)
#         print("Finished in: ", time.time() - start_q)

#         # 4. Construct the symmetric difference Di of the generated QR code to
#         # the original, for each Qi in qr_codes.
#         start_s = time.time()
#         print("Constructing symmetric differences...")

#         # Calculate dx for each pair of (q0, qi)
#         symmetric_diffs = [(qi, symmetric_diff(q0, qi)) for qi in qr_code_matrices]
#         print("Finished in: ", time.time() - start_s)

#         # 5. Calculate the ratios ri of modules in the symmetric differences
#         # that indicate a change from white to black.
#         start_sd = time.time()
#         print("Calculating ratios...")
#         # symmetric_diff_ratios = [
#         #     calculate_ratio(q0, qi, dx) for qi, dx in symmetric_diffs
#         # ]
#         args = [(calculate_ratio, (q0, qi, dx), {}) for qi, dx in symmetric_diffs]
#         symmetric_diff_ratios = common.POOL.map(unwrap, args)
#         print("Finished in: ", time.time() - start_sd)

#         # 6. Order the QR codes by ratio ri, descending. Codes where the number
#         # of codewords (not modules) that need to get changed from black to
#         # white is higher than the error-correcting capacity of the code can be
#         # omitted.
#         start_o = time.time()
#         print("Ordering codes...")
#         ordered_codes = order_codes_by_ratio(
#             qr_code_matrices, symmetric_diff_ratios, ecc
#         )
#         print("Finished in: ", time.time() - start_o)

#         # 7. Start with the first QR code Q1 (now sorted) and color white
#         # modules of Q0 that are black in Q1 black.
#         # Check after every module, whether the meaning of the QR code can be
#         # decoded and results in a different message than the original. Repeat
#         # this until a valid coloring is found (for the first b elements the
#         # check can be omitted, where b denotes the number of errors the
#         # BCH-encoding is capable of correcting plus one. If the resulting code
#         # Qi' can get decoded to message Mi, a solution was found.
#         start_verify = time.time()
#         print("Verifying solutions...")
#         # valid_code = verify_solution(q0, message, ordered_codes, image_name)
#         args = [
#             (is_code_valid, ((q0, message, ordered_codes[i]),), {})
#             for i in range(len(ordered_codes))
#         ]
#         valid_codes = []
#         result = common.POOL.map_async(unwrap, args)
#         for i, value in enumerate(result.get()):
#             # if value:
#             #     # common.POOL.close()
#             #     common.POOL.terminate()
#             #     common.POOL.join()
#             #     valid_code = value
#             #     break
#             if value:
#                 valid_codes.append((q0, message, ordered_codes[i], f"{image_name}_{i}"))
#         valid_code = None
#         if valid_codes:
#             valid_code = save_solution(*valid_codes[0])
#         print("Finished in: ", time.time() - start_verify)
#         print("Valid code: ", valid_code)
#         if valid_code:
#             return valid_code

#         # 8. The last step can be repeated for all Qi where the number of black
#         # modules in the symmetric difference Di is greater than the number of
#         # errors
#         # that can be corrected by the BCH-encoding (b).

#     return ""


def symmetric_diff(q0, q1):
    """Calculates symmetric difference between 2 QR codes.

    Symmetric difference is the set of modules that are different colors at the
    same position on both QrCodes q_0 and q_i.

    Args:
        q0: np.ndarray matrix representation of QR code
        q1: np.ndarray matrix representation of QR code
    Returns:
        A list diffs of two lists of tuples that represent (x, y) positions on
        the qr odes. The first list diffs[0] contains tuples representing all of
        the positions where the qr_0 module was white and qr_i module was black.
        The second list diffs[1] contains tuples representing the opposite:
        positions where qr_0 was black and qr_i was white. All (x, y) pairs in
        range (n, n) not included in either list are the same color in both qr_0
        and qr_i (xor of q0 and q1).
    """
    return np.logical_xor(q0, q1)


def calculate_ratio(qr0, qr1, dx):
    """Calculates ratio of size of symmetric_diff[0] to total elements in
    symmetric_diff.

    From two lists of unique length-2 tuples of integers that do not overlap,
    calculates the ratio of the number of elements in the first list to the
    total number of elements included in both lists.

    If both lists are empty, returns 1.

    Args:
        q0: np.ndarray matrix representation of QR code
        q1: np.ndarray matrix representation of QR code
        dx: matrix symmetric diff between q0 and q1
    Returns:
        ratio of first list length to length of combined lists
    """
    rx = np.logical_and(qr0, qr1)
    return np.linalg.norm(rx, 1) / np.linalg.norm(dx, 1)


def order_codes_by_ratio(qr_code_matrices, symmetric_diff_ratios, ecc):
    """Order qr_codes by symmetric_diff ratio r_i in descending order.

    Args:
        qr_codes: list of QrCode objects
        symmetric_diff_ratios: list of ratios r_i
        ecc: error correction capacity of target QR code
    Returns:
        list of ordered QrCode objects
    """

    # Order qr codes by symmetric_diff_ratio in descending order
    zipped = zip(symmetric_diff_ratios, qr_code_matrices)
    ordered = [
        (ri, qr_code)
        for ri, qr_code in sorted(zipped, key=lambda x: x[0], reverse=True)
    ]

    # Omit qr codes where r_i is less than the error correcting capacity of
    # target qr code
    ecc = qr.get_ecc_level_value(ecc)
    valid = []
    for ri, qr_code in ordered:
        # if ri >= ecc:
        #     valid.append(qr_code)
        valid.append(qr_code)
    return valid


def save_solution(q0, m0, qx, image_name):
    dx = np.logical_xor(q0, qx)
    rx = np.logical_and(qx, dx)
    qx_prime = np.logical_or(q0, rx)

    output_path = "./demo/" + image_name + ".png"
    qr.qr_matrix_image(qx_prime, output_path)
    diff = qr.qr_diff(
        q0, qx_prime
    )  # a greyscale numpy array with values that are either 0 (black) or 255

    # q0 is numpy array that has values of either 0 or 1

    greyscale_q0 = qr.qr_matrix_rgb_from_matrix(
        q0
    )  # convert q0 to greyscale 0,1 -> 0,255
    rgb_q0 = cv2.cvtColor(
        greyscale_q0, cv2.COLOR_GRAY2RGB
    )  # convert greyscale original to RGB

    diff_color = cv2.cvtColor(diff, cv2.COLOR_GRAY2RGB)
    rgb_q0[np.all(diff_color == (0, 0, 0), axis=-1)] = (255, 0, 0)

    img = Image.fromarray(rgb_q0, "RGB")

    # save txt file of malicious url
    with open("demo/" + image_name + ".txt", "w") as file:
        file.write(m0)

    img.save("demo/" + "diff_" + image_name + ".png")
    return "diff_" + image_name  # decoded


def is_code_valid(args):
    # q0, m0, qx, image_name = args
    q0, m0, qx = args
    dx = np.logical_xor(q0, qx)
    rx = np.logical_and(qx, dx)
    qx_prime = np.logical_or(q0, rx)

    # Check after every module, whether the meaning of the QR code can be
    # decoded and results in a different message than the original.
    decoded = qr.decode_qr_matrix(qx_prime)
    if not decoded:
        return False
    return True if decoded != m0 else False
    # if not decoded:
    #     return
    # if decoded != m0:
    #     return save_solution(q0, m0, qx_prime, image_name)


def verify_solution(q0, m0, ordered_qr_codes, image_name):
    """
    Args:
        q0: QrCode object
        m0: message in q0
        ordered_qr_codes: list of QrCode objects produced by order_codes_by_ratio()
    Returns:
        list of valid QR code matrices
    """
    # 7. Start with the first QR code Q1 (now sorted) and color white modules of
    # Q0 that are black in Q1 black.
    # Check after every module, whether the meaning of the QR code can be
    # decoded and results in a different message than the original. Repeat this
    # until a valid coloring is found (for the first b elements the check can be
    # omitted, where b denotes the number of errors the BCH-encoding is capable
    # of correcting plus one.
    # If the resulting code Qi can get decoded to message Mi, a solution was
    # found.
    # In step seven, the following optimization can be used: Instead of coloring
    # module by module, we simply change all modules that can be changed by only
    # using black color at once and thus generate Qx by applying the fast and
    # simple element-wise OR-function: Qx = Q0 OR Rx, (OR = element-wise OR).
    # Q0 = target code,
    # Qx = generated code,
    # Rx = Qx AND Dx (AND = element-wise AND)
    # Dx = Q0 XOR Qx,
    # Qx = code in qr_codes

    args = [
        (q0, m0, ordered_qr_codes[i], image_name, i)
        for i in range(len(ordered_qr_codes))
    ]

    for arg in args:
        output_path = is_code_valid(arg)
        if output_path:
            return output_path
    return


if __name__ == "__main__":
    common.init_pool(num_processes=1)
    try:
        # generate_malicious_qr(
        #     message="https://www.thinkific.com",
        #     ecc="LOW",
        #     version=2,
        #     mask=2,
        #     image_name="thinkific",
        # )
        generate_malicious_qr(
            message="http://yahoo.at",
            ecc="LOW",
            version=1,
            mask=7,
            image_name="yahoo",
        )
    except KeyboardInterrupt:
        if common.POOL:
            # common.POOL.close()
            common.POOL.terminate()
            common.POOL.join()
